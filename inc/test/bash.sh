#===========[BASH]==========
#version
v="`bash --version`";vL=($v);v=${vL[3]}

#name							#last version					#current version		#nb test
DATA[0,0]="bash"				;DATA[0,1]="4.3"				;DATA[0,2]="$v"			;DATA[0,3]=0
#CVE name						#CVE date						#CVE level				#CVE version list 
#DATAVUL[0,0,0]=""	;DATAVUL[0,0,1]=""	;DATAVUL[1,0,2]=""	;DATAVUL[1,0,3]=""

