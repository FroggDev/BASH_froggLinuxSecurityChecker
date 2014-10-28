#===========[NTPD]==========
#version
v="`ntpq -crv`";vL=(${v//@/ });v=${vL[8]}

#name							#last version					#current version		#nb test
DATA[2,0]="ntpd"				;DATA[2,1]="4.2.7p26"			;DATA[2,2]="$v"			;DATA[2,3]=1
#CVE name						#CVE date						#CVE level				#CVE version list 
DATAVUL[2,0,0]="CVE-2013-5211"	;DATAVUL[2,0,1]="2014/01/02"	;DATAVUL[2,0,2]="5.0"	;DATAVUL[2,0,3]="4.2.7"	
