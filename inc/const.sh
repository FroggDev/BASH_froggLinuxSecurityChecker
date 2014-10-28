# DECLARE VARS
# ============
#===Colors
INFOun="\e[4m"			#underline
INFObo="\e[1m"			#bold
INFOb="${INFObo}\e[34m"	#blue
INFOr="${INFObo}\e[31m"	#red

NORM="\e[0m"
GOOD="\e[1m\e[97m\e[42m"
OLD="\e[1m\e[97m\e[45m"
CHECK="\e[1m\e[97m\e[43m"
WARN="\e[1m\e[97m\e[48;5;208m"
ERR="\e[1m\e[97m\e[41m"
#===host infos
#default server IP
host="127.0.0.1"
#test ssl port
port=443
#===misc
#number of vulnerabilities found
vulFound=""
#Current title number (cannot be changed)
currNb=1
#Nb of daemon tested
nbTest=5