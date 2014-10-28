# DECLARE FUNCS
# =============

#==COLOR STYLE TYPE

#echo with "good" result color
good()
{
echo -e "${GOOD}$1${NORM}"
}

#echo with "warn" result color
warn()
{
echo -e "${WARN}$1${NORM}"
}

#echo with "check" result color
check()
{
echo -e "${CHECK}$1${NORM}"
}

#echo with "old" result color
old()
{
echo -e "${OLD}$1${NORM}"
}

#echo with "err" result color
err()
{
echo -e "${ERR}$1${NORM}"
}

# echo an title format
title()
{
echo -e "\n${INFOb}${INFOun}$1${NORM}"
}

#==TEST RESULT

#echo vulnerable in orange/red with param
testko()
{
case "$scary" in
0)	warn "Non-exploitable to $1 | score : $2/10";;
1)	err "Vulnerable to $1 | score : $2/10";locFound=$((locFound + 1));;
2)	warn "Vulnerable but may be non-exploitable to $1 | score : $2/10";;
esac
}

#echo not vulnerable in green with param
testok()
{
good "Not vulnerable to $1";
}

#==VERSION TEST

#Test if str is in array return 1 if is in array
testIsInArray()
{
#replace $1 param by FOUND if has been found in $2 array
arrTmp=${2/${1}/FOUND}
#if both arrays are equals then return 0 else return 1
[ "${arrTmp[*]}" == "${2}" ] && return 0 || return 1
}

#check if version is in vulnerable list
testVersion()
{
#set lvl to important
scary=1
#test if $1 is in $3 array
testIsInArray "$1" "$3"
#if found then warn else ok
[ $? = 1 ]&&testko "$2" "$4"
}

#check if version of $1 > $2
checkVersion()
{
#add shell option not sensitive
shopt -s nocasematch
if [ $1 = *beta* -o $1 = *alpha* -o $1 = *gamma* ];then
	return 2
else
	vSort=`printf "$1\n$2" | sort -V`
	vArr=(${vSort//\n/ })
	[ ${vArr[1]} = $1 ]&& return 0 || return 1
fi
#remove shell option not sensitive
shopt -u nocasematch
}

versionCheckMsg()
{
checkVersion "$2" "$3"
case "$?" in
0)	good "your $1 version '$2' is up to date";;
1)	warn "your $1 version is outdated : $2 versus $3";;
2)	old "your $1 version is a beta version:'$2', you need to update it";;	
esac
}

#==DAEMON TEST

# check if command exist
canExec()
{
type "$1" &> /dev/null ;
}

#add special include if exist
incSpeTest()
{
fileInc="${spe}${1}.sh"
if [ -e $fileInc ];then
. $fileInc
fi
}

#include test files list
incTests()
{
for tests in ${tst}*
do
	if [ -f ${tests} ];then
. $tests
	fi
done
}