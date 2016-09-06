#	Placed in the Public Domain.

tid="server config include"

cat > $OBJ/sshd_config.i << _EOF
HostKey $OBJ/host.eda25519
Match host a
	Banner /aa

Match host b
	Banner /bb
	Include $OBJ/sshd_config.i.*

Match host c
	Include $OBJ/sshd_config.i.*
	Banner /cc

Match host m
	Include $OBJ/sshd_config.i.*

Match Host d
	Banner /dd

Match Host e
	Banner /ee
	Include $OBJ/sshd_config.i.*

Match Host f
	Include $OBJ/sshd_config.i.*
	Banner /ff

Match Host n
	Include $OBJ/sshd_config.i.*
_EOF

cat > $OBJ/sshd_config.i.0 << _EOF
Match host xxxxxx
_EOF

cat > $OBJ/sshd_config.i.1 << _EOF
Match host a
	Banner /aaa

Match host b
	Banner /bbb

Match host c
	Banner /ccc

Match Host d
	Banner /ddd

Match Host e
	Banner /eee

Match Host f
	Banner /fff
_EOF

cat > $OBJ/sshd_config.i.2 << _EOF
Match host a
	Banner /aaaa

Match host b
	Banner /bbbb

Match host c
	Banner /cccc

Match Host d
	Banner /dddd

Match Host e
	Banner /eeee

Match Host f
	Banner /ffff

Match all
	Banner /xxxx
_EOF

trial() {
	_host="$1"
	_exp="$2"
	trace "Testing the match with host=$_host"
	${REAL_SSHD} -f $OBJ/sshd_config.i -T -C "host=$_host,user=test,addr=127.0.0.1" > $OBJ/sshd_config.out ||
		fatal "ssh config parse failed"
	_got=`grep -i '^banner ' $OBJ/sshd_config.out | awk '{print $2}'`
	if test "x$_exp" != "x$_got" ; then
		fail "host $_host include fail: expected $_exp got $_got"
	fi
}

trial a /aa
trial b /bb
trial c /ccc
trial d /dd
trial e /ee
trial f /fff
trial m /xxxx
trial n /xxxx
trial x none

# Prepare an included config with an error.

cat > $OBJ/sshd_config.i.3 << _EOF
Banner xxxx
	Junk
_EOF

${REAL_SSHD} -f $OBJ/sshd_config.i -C "host=a,user=test,addr=127.0.0.1" 2>/dev/null && \
	fail "sshd include allowed invalid config"

${REAL_SSHD} -f $OBJ/sshd_config.i -C "host=x,user=test,addr=127.0.0.1" 2>/dev/null && \
	fail "sshd include allowed invalid config"

rm -f $OBJ/sshd_config.i.*

# Ensure that a missing include is not fatal.
cat > $OBJ/sshd_config.i << _EOF
HostKey $OBJ/host.ed25519
Include $OBJ/sshd_config.i.*
Banner /aa
_EOF

trial a /aa

# Ensure that Match/Host in an included config does not affect parent.
cat > $OBJ/sshd_config.i.x << _EOF
Match host x
_EOF

trial a /aa

cat > $OBJ/sshd_config.i.x << _EOF
Match Host x
_EOF

trial a /aa

# Ensure the empty include directive is not accepted
cat > $OBJ/sshd_config.i.x << _EOF
Include
_EOF

${REAL_SSHD} -f $OBJ/sshd_config.i.x -C "host=x,user=test,addr=127.0.0.1" 2>/dev/null && \
	fail "sshd allowed empty Include option"

# cleanup
rm -f $OBJ/sshd_config.i $OBJ/sshd_config.i.* $OBJ/sshd_config.out
