# POODLE
# ------
#CVE-2014-3566
out="`echo x | timeout 5 ${DATA[$i,0]} s_client -ssl3 -connect ${host}:${port} 2>/dev/null`"
ret=$?
case "$ret" in
0)	scary=1;testko "CVE-2014-3566 (original poodle)" "4.3";;
124)warn "timeout connecting to host $host:$port\n";;
1)
	out=`echo $out | perl -pe 's|.*Cipher is (.*?) .*|$1|'`;
	if [ "$out" == "0000" ] || [ "$out" == "(NONE)" ];then
		testok "CVE-2014-3566 (original poodle)"
	fi
;;
*)	check "warning: $ret isn't a valid code while connecting to host $host:$port\n";;
esac