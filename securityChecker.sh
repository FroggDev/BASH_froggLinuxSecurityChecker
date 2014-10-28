#!/bin/bash

# ############################ #
#            _ __ _            #
#        ((-)).--.((-))        #
#        /     ''     \        # 
#       (   \______/   )       #  
#        \    (  )    /        #
#        / /~~~~~~~~\ \        #
#   /~~\/ /          \ \/~~\   #
#  (   ( (            ) )   )  #
#   \ \ \ \          / / / /   #
#   _\ \/  \.______./  \/ /_   #
#   ___/ /\__________/\ \___   #
# ############################ #
# by Frogg	on 2014/10/21      #
# => admin@frogg.fr			   #
# Linux Vulnerabilities Tester #
# ############################ #
#
# BASED ON WORK FROM 
# ==================
# Hanno Böck (hanno@hboeck.de - for shellshock)
# Dan Varga (dvarga@redhat.com - for poodle) 
#
# BASH VULNERABILITIES TESTED
# ===========================
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7186
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7187
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6277
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
#
# OPENSSL VULNERABILITIES TESTED
# ===========================
# https://www.openssl.org/news/vulnerabilities.html

###################################
# TODO LIST :
# * add test if openssl installed
# * improve checkVersion function
#   - split char as parameters with "." as default
#   - count array and while on it, to have dynamic levels
###################################

# DECLARE FUNCS & VARS
# ====================
#number of vuln,erabilities found
vulFound=0
#test server ip
host="127.0.0.1"
#test ssl port
port=443
#test if openssl version < 0.9.8 (then can be tested, too old)
vOsMini="0.9.8"

#echo vulnerable in orange/red with param
warn()
{
case "$scary" in
0)	echo -e "\e[1m\e[97m\e[42mNon-exploitable to $1\e[0m";;
1)	echo -e "\e[1m\e[97m\e[41mVulnerable to $1\e[0m";vulFound=$((vulFound + 1));;
2)	echo -e "\e[1m\e[97m\e[48;5;208mVulnerable but may be non-exploitable to $1\e[0m";;
esac
}

#echo not vulnerable in green with param
good()
{
echo -e "\e[1m\e[97m\e[48;5;22mNot vulnerable to $1\e[0m"
}

#Test if str is in array
testIsInArray()
{
#replace $1 param by FOUND if has been found in $2 array
arrTmp=${2/${1}/FOUND}
#if both arrays are equals then return 0 else return 1
[ "${arrTmp[*]}" == "${2}" ] && return 0 || return 1
}

#check if openssl version is in vulnerable list
testOpenSSLVersion()
{
#test if $1 is in $3 array
testIsInArray "$1" "$3"
#if found then warn else ok
[ $? = 1 ] && good "$2" || warn "$2"
}

#test if version1 is higher than version2 then return 1 else 0; return 2 if beta is in the name
#param => $1=vToTest / $2=vMax (vMax need to be x.x.x format)
checkVersion()
{
osv=(${1//./ })
vMini=(${2//./ })
if [ $1 == *beta* ];then
	return 2
else
	if [ $((${osv[0]//[[:alpha:]]/}  + 0)) -ge $((vMini[0] + 0)) ];then	
		if [ $((${osv[1]//[[:alpha:]]/}  + 0)) -ge $((vMini[1] + 0)) ];then
			if [ $((${osv[2]//[[:alpha:]]/} + 0)) -ge $((vMini[2] + 0)) ];then
				return 0
			else
				return 1
			fi			
		else
			return 1
		fi
	else
		return 1
	fi
fi
}

#convert string or float to number (and round it to roof)
function string_to_int ()
{
LANG=C
d=${1##*.}
if [[ ${#1} -eq ${#d} ]]; then
	d=0
fi
e=${1%.*}
e=${e//,/}
printf %.0f "$e.$d" 2>/dev/null
}
 

# SCRIPT TITLE BOX
# ================
#Create temp dir
tmpdir=`mktemp -d -t tmp.XXXXXXXX`
#Get bash type
[ -n "$1" ] && bash=$(which $1) || bash=$(which bash)
#Get openssl version
osv="`openssl version`"
arrOSV=(${osv// / })

#Display script start infos
echo -e "\n\e[1m\e[34m==============================="
echo -e " * Linux Vulnerabilities Tester"
$bash -c 'echo " * version $BASH_VERSION"'
echo -e " * Openssl version ${arrOSV[1]}"
echo -e "===============================\e[0m\n"


# VULNERABILITIES TESTS
# =====================

# ================>
# ================> BASH
# ================>

echo -e "\e[1m\e[4m1] Testing $bash Vulnerabilities\e[0m"

# SHELLSHOCK
# ----------

#r=`a="() { echo x;}" $bash -c a 2>/dev/null`
if [ -n "$(env 'a'="() { echo x;}" $bash -c a 2>/dev/null)" ]; then
	echo -e "\e[1m\e[97m\e[43mVariable function parser active, maybe vulnerable to unknown parser bugs\e[0m"
	scary=1
elif [ -n "$(env 'BASH_FUNC_a%%'="() { echo x;}" $bash -c a 2>/dev/null)" ]; then
	echo -e "\e[1m\e[97m\e[43mVariable function parser pre/suffixed [%%, upstream], bugs not exploitable\e[0m"
	scary=0
elif [ -n "$(env 'BASH_FUNC_a()'="() { echo x;}" $bash -c a 2>/dev/null)" ]; then
	#echo -e "\e[1m\e[97m\e[43mVariable function parser pre/suffixed [(), redhat], bugs not exploitable\e[0m"
	scary=0
elif [ -n "$(env '__BASH_FUNC<a>()'="() { echo x;}" $bash -c a 2>/dev/null)" ]; then
	echo -e "\e[1m\e[97m\e[43mVariable function parser pre/suffixed [__BASH_FUNC<..>(), apple], bugs not exploitable\e[0m"
	scary=0
else
	echo -e "\e[1m\e[97m\e[43mVariable function parser inactive, bugs not exploitable\e[0m"
	scary=0
fi

#CVE-2014-7187
$bash -c "`for i in {1..200}; do echo -n "for x$i in; do :;"; done; for i in {1..200}; do echo -n "done;";done`" 2>/dev/null
if [ $? != 0 ]; then
	warn "CVE-2014-7187 (nested loops off by one)"
else
	echo -e "\e[1m\e[97m\e[43mNon-reliable to CVE-2014-7187 : require address sanitizer\e[0m"
fi

#CVE-2014-7186 
$($bash -c "true $(printf '<<EOF %.0s' {1..80})" 2>$tmpdir/bashcheck.tmp)
ret=$?
grep AddressSanitizer $tmpdir/bashcheck.tmp > /dev/null
if [ $? == 0 ] || [ $ret == 139 ]; then
	warn "CVE-2014-7186 (redir_stack bug)"
else
	good "CVE-2014-7186 (redir_stack bug)"
fi

#CVE-2014-6278
if [ -n "$(env x='() { _;}>_[$($())] { echo x;}' $bash -c : 2>/dev/null)" ]; then
	warn "CVE-2014-6278 (lcamtuf bug #2)"
elif [ -n "$(env BASH_FUNC_x%%='() { _;}>_[$($())] { echo x;}' $bash -c : 2>/dev/null)" ]; then
	warn "CVE-2014-6278 (lcamtuf bug #2)"
elif [ -n "$(env 'BASH_FUNC_x()'='() { _;}>_[$($())] { echo x;}' $bash -c : 2>/dev/null)" ]; then
	warn "CVE-2014-6278 (lcamtuf bug #2)"
else
	good "CVE-2014-6278 (lcamtuf bug #2)"
fi

#CVE-2014-6277
$($bash -c "f(){ x(){ _;};x(){ _;}<<a;}" 2>/dev/null)
if [ $? != 0 ]; then
	warn "CVE-2014-6277 (lcamtuf bug #1)"
else
	good "CVE-2014-6277 (lcamtuf bug #1)"
fi

#CVE-2014-6271
r=`env x="() { :; }; echo x" $bash -c "" 2>/dev/null`
if [ -n "$r" ]; then
	warn "CVE-2014-6271 (original shellshock)"
else
	good "CVE-2014-6271 (original shellshock)"
fi

#CVE-2014-7169
pushd $tmpdir > /dev/null
env x='() { function a a>\' $bash -c echo 2>/dev/null > /dev/null
if [ -e echo ]; then
	warn "CVE-2014-7169 (taviso bug)"
else
	good "CVE-2014-7169 (taviso bug)"
fi
popd > /dev/null

# ================>
# ================> OPEN SSL
# ================>

echo -e "\n\e[1m\e[4m2] Testing OpenSSL Vulnerabilities\e[0m"

# POODLE
# ------

#CVE-2014-3566
out="`echo x | timeout 5 openssl s_client -ssl3 -connect ${host}:${port} 2>/dev/null`"
ret=$?
case "$ret" in
0)
	scary=1
	warn "CVE-2014-3566 (original poodle)"
;;
124)
	echo -e "\e[0m\e[1m\e[97m\e[43merror: timeout connecting to host $host:$port\e[0m\n";
;;
1)
	out=`echo $out | perl -pe 's|.*Cipher is (.*?) .*|$1|'`;
	if [ "$out" == "0000" ] || [ "$out" == "(NONE)" ];then
		good "CVE-2014-3566 (original poodle)"
	fi	
;;
*)
	echo -e "\e[0m\e[1m\e[97m\e[43mwarning: $ret isn't a valid code while connecting to host $host:$port\e[0m\n";
;;
esac


# openSSL 2014
# https://www.openssl.org/news/vulnerabilities.html
# ----------
#openssl version var 
ov=${arrOSV[1]}
scary=2

doSSLTest=0
checkVersion "$ov" "$vOsMini"
case "$?" in
0)	doSSLTest=1;;
1)	echo -e "\e[0m\e[1m\e[97m\e[43merror: your OpenSSL version is too old, you need to update it\e[0m\n";;
2)	echo -e "\e[0m\e[1m\e[97m\e[43merror: your OpenSSL version is a beta version, you need to update it\e[0m\n";;	
esac

if [ $doSSLTest = 1 ];then
#CVE-2014-3513: 15th October 2014
#Affected 1.0.1i, 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
ovList=(1.0.1i 1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1)
testOpenSSLVersion "$ov" "CVE-2014-3513: 15th October 2014" "${ovList[*]}"

#CVE-2014-3567: 15th October 2014
#Affected 1.0.1i, 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0n, 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8zb, 0.9.8za, 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g
ovList=(1.0.1i 1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0n 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8zb 0.9.8za 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g)
testOpenSSLVersion "$ov" "CVE-2014-3567: 15th October 2014" "${ovList[*]}"

#CVE-2014-3566: 15th October 2014
#Affected 1.0.1i, 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0n, 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8zb, 0.9.8za, 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1i 1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0n 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8zb 0.9.8za 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-3566: 15th October 2014" "${ovList[*]}"

#CVE-2014-3568: 15th October 2014
#Affected 1.0.1i, 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0n, 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8zb, 0.9.8za, 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1i 1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0n 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8zb 0.9.8za 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-3568: 15th October 2014" "${ovList[*]}"

#CVE-2014-3508: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8za, 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8za 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-3508: 6th August 2014" "${ovList[*]}"

#CVE-2014-5139: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1)
testOpenSSLVersion "$ov" "CVE-2014-5139: 6th August 2014" "${ovList[*]}"

#CVE-2014-3509: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0)
testOpenSSLVersion "$ov" "CVE-2014-3509: 6th August 2014" "${ovList[*]}"

#CVE-2014-3505: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8za, 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8za 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m)
testOpenSSLVersion "$ov" "CVE-2014-3505: 6th August 2014" "${ovList[*]}"

#CVE-2014-3506: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8za, 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8za 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-3506: 6th August 2014" "${ovList[*]}"

#CVE-2014-3507: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a
#Affected 0.9.8za, 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 0.9.8za 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o)
testOpenSSLVersion "$ov" "CVE-2014-3507: 6th August 2014" "${ovList[*]}"

#CVE-2014-3510: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1)
#Affected 1.0.0m, 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8za, 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0m 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8za 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-3510: 6th August 2014" "${ovList[*]}"

#CVE-2014-3511: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1)
testOpenSSLVersion "$ov" "CVE-2014-3511: 6th August 2014" "${ovList[*]}"

#CVE-2014-3512: 6th August 2014
#Affected 1.0.1h, 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
ovList=(1.0.1h 1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1)
testOpenSSLVersion "$ov" "CVE-2014-3512: 6th August 2014" "${ovList[*]}"

#CVE-2014-0224: 5th June 2014
#Affected 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-0224: 5th June 2014" "${ovList[*]}"

#CVE-2014-0221: 5th June 2014
#Affected 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-0221: 5th June 2014" "${ovList[*]}"

#CVE-2014-0195: 5th June 2014
#Affected 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o
ovList=(1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o)
testOpenSSLVersion "$ov" "CVE-2014-0195: 5th June 2014" "${ovList[*]}"

#CVE-2014-3470: 30th May 2014
#Affected 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-3470: 30th May 2014" "${ovList[*]}"

#CVE-2014-0198: 21st April 2014
#Affected 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
ovList=(1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0)
testOpenSSLVersion "$ov" "CVE-2014-0198: 21st April 2014" "${ovList[*]}"

#CVE-2010-5298: 8th April 2014
#Affected 1.0.1g, 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
ovList=(1.0.1g 1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0)
testOpenSSLVersion "$ov" "CVE-2010-5298: 8th April 2014" "${ovList[*]}"

#CVE-2014-0160: 7th April 2014
#Affected 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
ovList=(1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1)
testOpenSSLVersion "$ov" "CVE-2014-0160: 7th April 2014" "${ovList[*]}"

#CVE-2014-0076: 14th February 2014
#Affected 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
#Affected 1.0.0l, 1.0.0k, 1.0.0j, 1.0.0i, 1.0.0g, 1.0.0f, 1.0.0e, 1.0.0d, 1.0.0c, 1.0.0b, 1.0.0a, 1.0.0
#Affected 0.9.8y, 0.9.8x, 0.9.8w, 0.9.8v, 0.9.8u, 0.9.8t, 0.9.8s, 0.9.8r, 0.9.8q, 0.9.8p, 0.9.8o, 0.9.8n, 0.9.8m, 0.9.8l, 0.9.8k, 0.9.8j, 0.9.8i, 0.9.8h, 0.9.8g, 0.9.8f, 0.9.8e, 0.9.8d, 0.9.8c, 0.9.8b, 0.9.8a, 0.9.8
ovList=(1.0.1f 1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1 1.0.0l 1.0.0k 1.0.0j 1.0.0i 1.0.0g 1.0.0f 1.0.0e 1.0.0d 1.0.0c 1.0.0b 1.0.0a 1.0.0 0.9.8y 0.9.8x 0.9.8w 0.9.8v 0.9.8u 0.9.8t 0.9.8s 0.9.8r 0.9.8q 0.9.8p 0.9.8o 0.9.8n 0.9.8m 0.9.8l 0.9.8k 0.9.8j 0.9.8i 0.9.8h 0.9.8g 0.9.8f 0.9.8e 0.9.8d 0.9.8c 0.9.8b 0.9.8a 0.9.8)
testOpenSSLVersion "$ov" "CVE-2014-0076: 14th February 2014" "${ovList[*]}"

#CVE-2013-4353: 6th January 2014
#Affected 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, 1.0.1
ovList=(1.0.1e 1.0.1d 1.0.1c 1.0.1b 1.0.1a 1.0.1)
testOpenSSLVersion "$ov" "CVE-2013-4353: 6th January 2014" "${ovList[*]}"
fi

# SCRIPT CLEANING
# ===============
# reset display colors & display result
echo -e "\n\e[1m\e[34m==============================="
echo -e " * end of tests"
case "$vulFound" in
0)echo -e "\e[34m * No Vulnerability found, congrats ! \n";;
1)echo -e "\e[31m * $vulFound Vulnerability found \n /!\ you should update your system /!\ ";;
*)echo -e "\e[31m * $vulFound Vulnerabilities found \n /!\ you should update your system /!\ ";;
esac
echo -e "\e[34m===============================\e[0m\n"

# remove temp folder
rm -rf $tmpdir
