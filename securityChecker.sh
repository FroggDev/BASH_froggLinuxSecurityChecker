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
# Linux Vulnerabilities Tester #
# by Frogg on 2014/10/21       #
# >Version 1.002               #
# >updated on 2014/10/28       #
# >admin@frogg.fr              #
# ############################ #

# BASED ON WORK FROM
# ==================
# Hanno Böck (hanno@hboeck.de - for shellshock)
# Dan Varga (dvarga@redhat.com - for poodle)
#
# NATIONAL VULNERABILITY DATABASE
# ===============================
# http://web.nvd.nist.gov/view/vuln/detail?vulnId={HERE_CVE-ID}
# http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=mysql

###################################
# TODO LIST :
# * add more services test
# * try auto create file (inc/test/) from http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=mysql
#   depending of added manually daemon on script call
#   with ask for version script to get daemon script
###################################

# clean "<<1/4*" from file
unBom()
{
iconv -c -f utf8 -t ISO88591 $1 | iconv -f ISO88591 -t utf8 > temp.$$ && mv temp.$$ $1;
}

#clean ^M
unCtrlM()
{
tr -d '\r' < $1 > temp.$$ && mv temp.$$ $1
}

#clean all files from
cleanDir()
{
for file in $1/*;do
	if [ -f $file ];then
		unBom $file;unCtrlM $file
	else
		cleanDir $file
	fi
done
}

# START SCRIPT
# ============

#===Includes
inc="inc/"
tst="${inc}test/"
spe="${tst}special/"

cleanDir ${inc}

. ${inc}const.sh
. ${inc}func.sh

#declare matrix of datas & include all test files
declare -A DATA
declare -A DATAVUL
incTests

# SCRIPT TITLE BOX
# ================

#Display script start infos
echo -e "\n${INFOb}==============================="
echo -e " * Linux Vulnerabilities Tester"
echo -e " * on server $host"
echo -e " *"
echo -e " * Daemon to test :"
echo -e " * ----------------"
for ((i=0;i<nbTest;i++));do
	#test if daemon exist
	if canExec ${DATA[$i,0]}
		echo -e " * ${DATA[$i,0]^^} version ${DATA[$i,2]}";
	fi
done
echo -e "===============================${NORM}"

# SCRIPT START
# ============
#Doing all test
for ((i=0;i<nbTest;i++)) do
	#test if daemon exist
	canExec ${DATA[$i,0]}
	if [ $? = 0 ];then
		#if local vulnerability has been found
		locFound=0
		#display title
		title "${currNb}] Testing ${DATA[$i,0]^^} Vulnerabilities"
		#version check
		versionCheckMsg "${DATA[$i,0]^^}" "${DATA[$i,2]}" "${DATA[$i,1]}"
		#add special vulnerability test include if exist
		incSpeTest ${DATA[$i,0]}
		#test all vulnerabilities
		for ((j=0;j<DATA[$i,3];j++)) do
			v=(${DATAVUL[$i,$j,3]})
			testVersion "${DATA[$i,2]}" "${DATAVUL[$i,$j,0]}: ${DATAVUL[$i,$j,1]}" "${v[*]}" "${DATAVUL[$i,$j,2]}"
		done
		#if no vulnerability found send a ok message
		[ $locFound = 0 ] && good "[ RESULT ] your ${DATA[$i,0]^^} version has no known vulnerabilities" || vulFound="${vulFound} ${DATA[$i,0]^^}"
		#add +1 to current test number
		currNb=$((currNb + 1))
	fi
done

# SCRIPT CLEANING
# ===============
# reset display colors & display result
echo -e "\n${INFOb}==============================="
echo -e " * end of tests"
if [ "$vulFound" = "" ]; then
	echo -e "${INFOb} * No Vulnerability found, congrats ! "
else
	echo -e "${INFOr} * Vulnerabilities found on:"
	array=( ${vulFound} )
	for i in "${array[@]}";do
		echo "   - ${i}"
	done
	echo -e "/!\ you should update your system /!\ "
fi
echo -e "${INFOb}===============================${NORM}\n"