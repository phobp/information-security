#----------------------------------------------------------------------------
#Programming Lab-01   Generate encryption key / IV and save to binary files
#
#Written By  :   1- Dr. Mohamed Aboutabl
#Submitted on: 
#----------------------------------------------------------------------------
#!/bin/bash
   
echo
echo "Script to run Programming Lab-01"
echo "By: Mohamed Aboutabl"
echo
   
rm -f genkey       key.bin             iv.bin
rm -f amal/amal    amal/logAmal.txt    amal/ciphertext.bin
rm -f basim/basim  basim/logBasim.txt  basim/decryptedtext.bin
   
echo "=============================="
echo "Compiling all source code"
   gcc genkey.c                    -o genkey        -lcrypto
   gcc amal/amal.c    myCrypto.c   -o amal/amal     -lcrypto
   gcc basim/basim.c  myCrypto.c   -o basim/basim   -lcrypto
   
   echo
   echo "Generating Key/IV"
   ./genkey
   
   echo
   echo "Executing Amal"
   amal/amal
   
   echo
   echo "Executing Basim"
   basim/basim
   
   echo
   echo "======  Amal's  LOG  ========="
   cat  amal/logAmal.txt
   
   echo
   echo "======  Basim's  LOG  ========="
   cat  basim/logBasim.txt
   echo
   echo
