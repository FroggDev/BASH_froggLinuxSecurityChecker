#Create temp dir
tmpdir=`mktemp -d -t tmp.XXXXXXXX`
[ -n "$1" ] && bash=$(which $1) || bash=$(which bash)

# SHELLSHOCK
# ----------

if [ -n "$(env 'a'="() { echo x;}" $bash -c a 2>/dev/null)" ]; then
	check "Variable function parser active, maybe vulnerable to unknown parser bugs"
	scary=1
elif [ -n "$(env 'BASH_FUNC_a%%'="() { echo x;}" $bash -c a 2>/dev/null)" ]; then
	check "Variable function parser pre/suffixed [%%, upstream], bugs not exploitable"
	scary=0
elif [ -n "$(env 'BASH_FUNC_a()'="() { echo x;}" $bash -c a 2>/dev/null)" ]; then
	check "Variable function parser pre/suffixed [(), redhat], bugs not exploitable"
	scary=0
elif [ -n "$(env '__BASH_FUNC<a>()'="() { echo x;}" $bash -c a 2>/dev/null)" ]; then
	check "Variable function parser pre/suffixed [__BASH_FUNC<..>(), apple], bugs not exploitable"
	scary=0
else
	check "Variable function parser inactive, bugs not exploitable"
	scary=0
fi

#CVE-2014-7187
$bash -c "`for i in {1..200}; do echo -n "for x$i in; do :;"; done; for i in {1..200}; do echo -n "done;";done`" 2>/dev/null
if [ $? != 0 ]; then
	testko "CVE-2014-7187 (nested loops off by one)" "10"
else
	check "Non-reliable to CVE-2014-7187 : require address sanitizer"
fi

#CVE-2014-7186
$($bash -c "true $(printf '<<EOF %.0s' {1..80})" 2>$tmpdir/bashcheck.tmp)
ret=$?
grep AddressSanitizer $tmpdir/bashcheck.tmp > /dev/null
if [ $? == 0 ] || [ $ret == 139 ]; then
	testko "CVE-2014-7186 (redir_stack bug)" "10"
else
	testok "CVE-2014-7186 (redir_stack bug)"
fi

#CVE-2014-6278
if [ -n "$(env x='() { _;}>_[$($())] { echo x;}' $bash -c : 2>/dev/null)" ]; then
	testko "CVE-2014-6278 (lcamtuf bug #2)" "10"
elif [ -n "$(env BASH_FUNC_x%%='() { _;}>_[$($())] { echo x;}' $bash -c : 2>/dev/null)" ]; then
	testko "CVE-2014-6278 (lcamtuf bug #2)" "10"
elif [ -n "$(env 'BASH_FUNC_x()'='() { _;}>_[$($())] { echo x;}' $bash -c : 2>/dev/null)" ]; then
	testko "CVE-2014-6278 (lcamtuf bug #2)" "10"
else
	testok "CVE-2014-6278 (lcamtuf bug #2)"
fi

#CVE-2014-6277
$($bash -c "f(){ x(){ _;};x(){ _;}<<a;}" 2>/dev/null)
if [ $? != 0 ]; then
	testko "CVE-2014-6277 (lcamtuf bug #1)" "10"
else
	testok "CVE-2014-6277 (lcamtuf bug #1)"
fi

#CVE-2014-6271
r=`env x="() { :; }; echo x" $bash -c "" 2>/dev/null`
if [ -n "$r" ]; then
	testko "CVE-2014-6271 (original shellshock)" "10"
else
	testok "CVE-2014-6271 (original shellshock)"
fi

#CVE-2014-7169
pushd $tmpdir > /dev/null
env x='() { function a a>\' $bash -c echo 2>/dev/null > /dev/null
if [ -e echo ]; then
	testko "CVE-2014-7169 (taviso bug)" "10"
else
	testok "CVE-2014-7169 (taviso bug)"
fi
popd > /dev/null

# remove temp folder
rm -rf $tmpdir