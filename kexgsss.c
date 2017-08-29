/*
 * Copyright (c) 2001-2009 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef GSSAPI

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "ssh2.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh-gss.h"
#include "monitor_wrap.h"
#include "misc.h"      /* servconf.h needs misc.h for struct ForwardOptions */
#include "servconf.h"
#include "ssh-gss.h"
#include "digest.h"
#include "ssherr.h"

extern ServerOptions options;

int
kexgss_server(struct ssh *ssh)
{
	OM_uint32 maj_status, min_status;

	/*
	 * Some GSSAPI implementations use the input value of ret_flags (an
	 * output variable) as a means of triggering mechanism specific
	 * features. Initializing it to zero avoids inadvertently
	 * activating this non-standard behaviour.
	 */

	OM_uint32 ret_flags = 0;
	gss_buffer_desc gssbuf, recv_tok, msg_tok;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	Gssctxt *ctxt = NULL;
	u_int slen, klen;
	int kout;
	u_char *kbuf;
	DH *dh;
	int min = -1, max = -1, nbits = -1;
	int cmin = -1, cmax = -1; /* client proposal */
	const BIGNUM *pub_key, *dh_p, *dh_g;
	BIGNUM *shared_secret = NULL;
	BIGNUM *dh_client_pub = NULL;
	int type = 0;
	gss_OID oid;
	char *mechs;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;

	/* Initialise GSSAPI */

	/* If we're rekeying, privsep means that some of the private structures
	 * in the GSSAPI code are no longer available. This kludges them back
	 * into life
	 */
	if (!ssh_gssapi_oid_table_ok()) {
		mechs = ssh_gssapi_server_mechanisms();
		free(mechs);
	}

	debug2("%s: Identifying %s", __func__, ssh->kex->name);
	oid = ssh_gssapi_id_kex(NULL, ssh->kex->name, ssh->kex->kex_type);
	if (oid == GSS_C_NO_OID)
	   fatal("Unknown gssapi mechanism");

	debug2("%s: Acquiring credentials", __func__);

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctxt, oid))))
		fatal("Unable to acquire credentials for the server");

	switch (ssh->kex->kex_type) {
	case KEX_GSS_GRP1_SHA1:
		dh = dh_new_group1();
		break;
	case KEX_GSS_GRP14_SHA1:
	case KEX_GSS_GRP14_SHA256:
		dh = dh_new_group14();
		break;
	case KEX_GSS_GRP16_SHA512:
		dh = dh_new_group16();
		break;
	case KEX_GSS_GEX_SHA1:
		debug("Doing group exchange");
		packet_read_expect(SSH2_MSG_KEXGSS_GROUPREQ);
		/* store client proposal to provide valid signature */
		cmin = packet_get_int();
		nbits = packet_get_int();
		cmax = packet_get_int();
		min = MAX(DH_GRP_MIN, cmin);
		max = MIN(DH_GRP_MAX, cmax);
		packet_check_eom();
		if (max < min || nbits < min || max < nbits)
			fatal("GSS_GEX, bad parameters: %d !< %d !< %d",
			    min, nbits, max);
		dh = PRIVSEP(choose_dh(min, nbits, max));
		if (dh == NULL)
			packet_disconnect("Protocol error: no matching group found");

		DH_get0_pqg(dh, &dh_p, NULL, &dh_g);
		packet_start(SSH2_MSG_KEXGSS_GROUP);
		packet_put_bignum2(dh_p);
		packet_put_bignum2(dh_g);
		packet_send();

		packet_write_wait();
		break;
	default:
		fatal("%s: Unexpected KEX type %d", __func__, ssh->kex->kex_type);
	}

	dh_gen_key(dh, ssh->kex->we_need * 8);

	do {
		debug("Wait SSH2_MSG_GSSAPI_INIT");
		type = packet_read();
		switch(type) {
		case SSH2_MSG_KEXGSS_INIT:
			if (dh_client_pub != NULL)
				fatal("Received KEXGSS_INIT after initialising");
			recv_tok.value = packet_get_string(&slen);
			recv_tok.length = slen;

			if ((dh_client_pub = BN_new()) == NULL)
				fatal("dh_client_pub == NULL");

			packet_get_bignum2(dh_client_pub);

			/* Send SSH_MSG_KEXGSS_HOSTKEY here, if we want */
			break;
		case SSH2_MSG_KEXGSS_CONTINUE:
			recv_tok.value = packet_get_string(&slen);
			recv_tok.length = slen;
			break;
		default:
			packet_disconnect(
			    "Protocol error: didn't expect packet type %d",
			    type);
		}

		maj_status = PRIVSEP(ssh_gssapi_accept_ctx(ctxt, &recv_tok,
		    &send_tok, &ret_flags));

		free(recv_tok.value);

		if (maj_status != GSS_S_COMPLETE && send_tok.length == 0)
			fatal("Zero length token output when incomplete");

		if (dh_client_pub == NULL)
			fatal("No client public key");

		if (maj_status & GSS_S_CONTINUE_NEEDED) {
			debug("Sending GSSAPI_CONTINUE");
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
			gss_release_buffer(&min_status, &send_tok);
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	if (GSS_ERROR(maj_status)) {
		if (send_tok.length > 0) {
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
		}
		fatal("accept_ctx died");
	}

	if (!(ret_flags & GSS_C_MUTUAL_FLAG))
		fatal("Mutual Authentication flag wasn't set");

	if (!(ret_flags & GSS_C_INTEG_FLAG))
		fatal("Integrity flag wasn't set");

	if (!dh_pub_is_valid(dh, dh_client_pub))
		packet_disconnect("bad client public DH value");

	klen = DH_size(dh);
	kbuf = xmalloc(klen);
	kout = DH_compute_key(kbuf, dh_client_pub, dh);
	if (kout < 0)
		fatal("DH_compute_key: failed");

	shared_secret = BN_new();
	if (shared_secret == NULL)
		fatal("kexgss_server: BN_new failed");

	if (BN_bin2bn(kbuf, kout, shared_secret) == NULL)
		fatal("kexgss_server: BN_bin2bn failed");

	memset(kbuf, 0, klen);
	free(kbuf);

	DH_get0_key(dh, &pub_key, NULL);
	hashlen = sizeof(hash);
	switch (ssh->kex->kex_type) {
	case KEX_GSS_GRP1_SHA1:
	case KEX_GSS_GRP14_SHA1:
	case KEX_GSS_GRP14_SHA256:
	case KEX_GSS_GRP16_SHA512:
		kex_dh_hash(ssh->kex->hash_alg,
		    ssh->kex->client_version, ssh->kex->server_version,
		    sshbuf_ptr(ssh->kex->peer), sshbuf_len(ssh->kex->peer),
		    sshbuf_ptr(ssh->kex->my), sshbuf_len(ssh->kex->my),
		    NULL, 0, /* Change this if we start sending host keys */
		    dh_client_pub, pub_key, shared_secret,
		    hash, &hashlen
		);
		break;
	case KEX_GSS_GEX_SHA1:
		kexgex_hash(
		    ssh->kex->hash_alg,
		    ssh->kex->client_version, ssh->kex->server_version,
		    sshbuf_ptr(ssh->kex->peer), sshbuf_len(ssh->kex->peer),
		    sshbuf_ptr(ssh->kex->my), sshbuf_len(ssh->kex->my),
		    NULL, 0,
		    cmin, nbits, cmax,
		    dh_p, dh_g,
		    dh_client_pub,
		    pub_key,
		    shared_secret,
		    hash, &hashlen
		);
		break;
	default:
		fatal("%s: Unexpected KEX type %d", __func__, ssh->kex->kex_type);
	}

	BN_clear_free(dh_client_pub);

	if (ssh->kex->session_id == NULL) {
		ssh->kex->session_id_len = hashlen;
		ssh->kex->session_id = xmalloc(ssh->kex->session_id_len);
		memcpy(ssh->kex->session_id, hash, ssh->kex->session_id_len);
	}

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_sign(ctxt,&gssbuf,&msg_tok))))
		fatal("Couldn't get MIC");

	packet_start(SSH2_MSG_KEXGSS_COMPLETE);
	packet_put_bignum2(pub_key);
	packet_put_string(msg_tok.value,msg_tok.length);

	if (send_tok.length != 0) {
		packet_put_char(1); /* true */
		packet_put_string(send_tok.value, send_tok.length);
	} else {
		packet_put_char(0); /* false */
	}
	packet_send();

	gss_release_buffer(&min_status, &send_tok);
	gss_release_buffer(&min_status, &msg_tok);

	if (gss_kex_context == NULL)
		gss_kex_context = ctxt;
	else
		ssh_gssapi_delete_ctx(&ctxt);

	DH_free(dh);

	kex_derive_keys_bn(ssh, hash, hashlen, shared_secret);
	BN_clear_free(shared_secret);
	kex_send_newkeys(ssh);

	/* If this was a rekey, then save out any delegated credentials we
	 * just exchanged.  */
	if (options.gss_store_rekey)
		ssh_gssapi_rekey_creds();
	return 0;
}

int
kexecgss_server(struct ssh *ssh)
{
	OM_uint32 maj_status, min_status;

	/*
	 * Some GSSAPI implementations use the input value of ret_flags (an
	 * output variable) as a means of triggering mechanism specific
	 * features. Initializing it to zero avoids inadvertently
	 * activating this non-standard behaviour.
	 */

	OM_uint32 ret_flags = 0;
	gss_buffer_desc gssbuf, recv_tok, msg_tok;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	Gssctxt *ctxt = NULL;
	u_int slen, klen = 0;
	u_char *kbuf;
	BIGNUM *shared_secret = NULL;
	int type = 0;
	gss_OID oid;
	char *mechs;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;
	u_char *client_pub = NULL;
	u_int client_pub_len = 0;
	const EC_GROUP *group = NULL;
	EC_POINT *client_public = NULL;
	EC_KEY *server_key = NULL;
	const EC_POINT *public_key;
	u_char c25519_server_key[CURVE25519_SIZE];
	u_char c25519_server_pubkey[CURVE25519_SIZE];
	struct sshbuf *c25519_shared_secret = NULL;
	struct sshbuf *Q_S;
	struct kex *kex = ssh->kex;
	int r;

	/* Initialise GSSAPI */

	/* If we're rekeying, privsep means that some of the private structures
	 * in the GSSAPI code are no longer available. This kludges them back
	 * into life
	 */
	if (!ssh_gssapi_oid_table_ok())
		if ((mechs = ssh_gssapi_server_mechanisms()))
			free(mechs);

	debug2("%s: Identifying %s", __func__, kex->name);
	oid = ssh_gssapi_id_kex(NULL, kex->name, kex->kex_type);
	if (oid == GSS_C_NO_OID)
	   fatal("Unknown gssapi mechanism");

	debug2("%s: Acquiring credentials", __func__);

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctxt, oid))))
		fatal("Unable to acquire credentials for the server");

	if ((Q_S = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/* 5. S generates an ephemeral key pair (do the allocations early) */
	switch (kex->kex_type) {
	case KEX_GSS_NISTP256_SHA256:
		if ((server_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if (EC_KEY_generate_key(server_key) != 1) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		group = EC_KEY_get0_group(server_key);
		public_key = EC_KEY_get0_public_key(server_key);

		sshbuf_put_ec(Q_S, public_key, group);
		break;
	case KEX_GSS_C25519_SHA256:
		kexc25519_keygen(c25519_server_key, c25519_server_pubkey);
#ifdef DEBUG_KEXECDH
		dump_digest("server private key:", c25519_server_key,
		    sizeof(c25519_server_key));
#endif
		sshbuf_put_string(Q_S, c25519_server_pubkey,
		    sizeof(c25519_server_pubkey));
		break;
	default:
		fatal("%s: Unexpected KEX type %d", __func__, kex->kex_type);
	}

	do {
		debug("Wait SSH2_MSG_GSSAPI_INIT");
		type = packet_read();
		switch(type) {
		case SSH2_MSG_KEXGSS_INIT:
			if (client_pub != NULL)
				fatal("Received KEXGSS_INIT after initialising");
			recv_tok.value = packet_get_string(&slen);
			recv_tok.length = slen;

			client_pub = packet_get_string(&client_pub_len);

			/* Send SSH_MSG_KEXGSS_HOSTKEY here, if we want */
			break;
		case SSH2_MSG_KEXGSS_CONTINUE:
			recv_tok.value = packet_get_string(&slen);
			recv_tok.length = slen;
			break;
		default:
			packet_disconnect(
			    "Protocol error: didn't expect packet type %d",
			    type);
		}

		maj_status = PRIVSEP(ssh_gssapi_accept_ctx(ctxt, &recv_tok,
		    &send_tok, &ret_flags));

		free(recv_tok.value);

		if (maj_status != GSS_S_COMPLETE && send_tok.length == 0)
			fatal("Zero length token output when incomplete");

		if (client_pub == NULL)
			fatal("No client public key");

		if (maj_status & GSS_S_CONTINUE_NEEDED) {
			debug("Sending GSSAPI_CONTINUE");
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
			gss_release_buffer(&min_status, &send_tok);
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	if (GSS_ERROR(maj_status)) {
		if (send_tok.length > 0) {
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
		}
		fatal("accept_ctx died");
	}

	if (!(ret_flags & GSS_C_MUTUAL_FLAG))
		fatal("Mutual Authentication flag wasn't set");

	if (!(ret_flags & GSS_C_INTEG_FLAG))
		fatal("Integrity flag wasn't set");

	/* 3. S verifies that the (client) key is valid */
	/* calculate shared secret */
	switch (kex->kex_type) {
	case KEX_GSS_NISTP256_SHA256:
		if (client_pub_len != 65)
			fatal("The received NIST-P256 key did not match"
			    "expected length (expected 65, got %d)", client_pub_len);

		if (client_pub[0] != POINT_CONVERSION_UNCOMPRESSED)
			fatal("The received NIST-P256 key does not have first octet 0x04");

		if ((client_public = EC_POINT_new(group)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}

		if (!EC_POINT_oct2point(group, client_public, client_pub,
		    client_pub_len, NULL))
			fatal("Can not decode received NIST-P256 client key");

		if (sshkey_ec_validate_public(group, client_public) != 0) {
			sshpkt_disconnect(ssh, "invalid client public key");
			r = SSH_ERR_MESSAGE_INCOMPLETE;
			goto out;
		}

		if (!EC_POINT_is_on_curve(group, client_public, NULL))
			fatal("Received NIST-P256 client key is not on curve");

		/* Calculate shared_secret */
		klen = (EC_GROUP_get_degree(group) + 7) / 8;
		if ((kbuf = malloc(klen)) == NULL ||
		    (shared_secret = BN_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if (ECDH_compute_key(kbuf, klen, client_public,
		    server_key, NULL) != (int)klen ||
		    BN_bin2bn(kbuf, klen, shared_secret) == NULL) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		break;
	case KEX_GSS_C25519_SHA256:
		if (client_pub_len != 32)
			fatal("The received curve25519 key did not match"
			    "expected length (expected 32, got %d)", client_pub_len);

		if (client_pub[client_pub_len-1] & 0x80)
			fatal("The received key has MSB of last octet set!");

		/* generate shared secret */
		if ((c25519_shared_secret = sshbuf_new()) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		if ((r = kexc25519_shared_key(c25519_server_key,
		    client_pub, c25519_shared_secret)) < 0)
			goto out;

		/* if all octets of the shared secret are zero octets,
		 * is already checked in kexc25519_shared_key() */
		break;
	default:
		fatal("%s: Unexpected KEX type %d", __func__, kex->kex_type);
	}

	hashlen = sizeof(hash);
	switch (kex->kex_type) {
	case KEX_GSS_NISTP256_SHA256:
		kex_ecdh_hash(
		    kex->hash_alg,
		    group,
		    kex->client_version,
		    kex->server_version,
		    sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
		    sshbuf_ptr(kex->my), sshbuf_len(kex->my),
		    NULL, 0,
		    client_public,
		    EC_KEY_get0_public_key(server_key),
		    shared_secret,
		    hash, &hashlen
		);
		break;
	case KEX_GSS_C25519_SHA256:
		kex_c25519_hash(
		    kex->hash_alg,
		    kex->client_version, kex->server_version,
		    sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
		    sshbuf_ptr(kex->my), sshbuf_len(kex->my),
		    NULL, 0,
		    client_pub, c25519_server_pubkey,
		    sshbuf_ptr(c25519_shared_secret), sshbuf_len(c25519_shared_secret),
		    hash, &hashlen
		);
		break;
	default:
		fatal("%s: Unexpected KEX type %d", __func__, kex->kex_type);
	}

	if (kex->session_id == NULL) {
		kex->session_id_len = hashlen;
		kex->session_id = xmalloc(kex->session_id_len);
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_sign(ctxt,&gssbuf,&msg_tok))))
		fatal("Couldn't get MIC");

	packet_start(SSH2_MSG_KEXGSS_COMPLETE);
	{
		const u_char *ptr;
		size_t len;
		sshbuf_get_string_direct(Q_S, &ptr, &len);
		packet_put_string(ptr, len);
	}
	packet_put_string(msg_tok.value, msg_tok.length);

	if (send_tok.length != 0) {
		packet_put_char(1); /* true */
		packet_put_string(send_tok.value, send_tok.length);
	} else {
		packet_put_char(0); /* false */
	}
	packet_send();

	gss_release_buffer(&min_status, &send_tok);
	gss_release_buffer(&min_status, &msg_tok);

	if (gss_kex_context == NULL)
		gss_kex_context = ctxt;
	else
		ssh_gssapi_delete_ctx(&ctxt);

	/* Finally derive the keys and send them */
	switch (kex->kex_type) {
	case KEX_GSS_NISTP256_SHA256:
		if ((r = kex_derive_keys_bn(ssh, hash, hashlen, shared_secret)) != 0)
			goto out;
		break;
	case KEX_GSS_C25519_SHA256:
		if ((r = kex_derive_keys(ssh, hash, hashlen, c25519_shared_secret)) != 0)
			goto out;
		break;
	default:
		fatal("%s: Unexpected KEX type %d", __func__, kex->kex_type);
	}
	if ((r = kex_send_newkeys(ssh)) != 0)
		goto out;

	/* If this was a rekey, then save out any delegated credentials we
	 * just exchanged.  */
	if (options.gss_store_rekey)
		ssh_gssapi_rekey_creds();
out:
	explicit_bzero(hash, sizeof(hash));
	if (Q_S)
		sshbuf_free(Q_S);
	if (client_pub)
		free(client_pub);
	switch (kex->kex_type) {
	case KEX_GSS_NISTP256_SHA256:
		if (server_key)
			EC_KEY_free(server_key);
		if (kbuf) {
			explicit_bzero(kbuf, klen);
			free(kbuf);
		}
		if (shared_secret)
			BN_clear_free(shared_secret);
		break;
	case KEX_GSS_C25519_SHA256:
		explicit_bzero(c25519_server_key, sizeof(c25519_server_key));
		sshbuf_free(c25519_shared_secret);
		break;
	}
	return r;
}
#endif /* GSSAPI */
