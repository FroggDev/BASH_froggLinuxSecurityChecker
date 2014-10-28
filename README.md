Linux Security Checker
======================
Test Exploit on a Linux server using bash for:
- bash
- exim
- mysql
- ntp
- openssl

* code to prevent ^M : sed -i 's/\r$//' securityChecker.sh
* to execute the script do "bash securityChecker.sh"
* the script auto-clean file into inc/ folder
* includes folder can be rename if they are replace in constants in securityChecker.sh
inc="inc/"
tst="${inc}test/"
spe="${tst}special/"
* inc/test/ folder contains all daemon to be tested, to add more daemon, just add another file in this folder named with daemon name
* inc/test/special/ contains special script to test daemon