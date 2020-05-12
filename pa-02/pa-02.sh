#!/bin/bash

# "Script to run PA-02"
# "Written by: Brendan Pho, Wesley Llamas

echo
echo

# Generate public/private key-pair for Basim
cd amal 
rm -f *.pem 
openssl  genpkey -algorithm RSA -out amal_priv_key.pem -pkeyopt rsa_keygen_bits:2048
openssl  rsa     -pubout        -in  amal_priv_key.pem -out     amal_pub_key.pem
#openssl  rsa     -text          -in  amal_priv_key.pem

cd ../basim

# Now, share Basim's public key with Amal
rm -f *.pem
ln -s  ../amal/amal_pub_key.pem  amal_pub_key.pem
cd ../

echo "=============================="
echo "Compiling all source code"
rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt bunny.cpy 
#rm -f bunny.mp4

#
#  Add the necessary commands to build th three executables: 
#       ./dispatcher      ,      amal/amal      ,      and  basim/basim
#
        gcc wrappers.c      dispatcher.c -o dispatcher
        gcc amal/amal.c     myCrypto.c   -o amal/amal   -lcrypto
        gcc basim/basim.c   myCrypto.c   -o basim/basim -lcrypto
       

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo
echo "======  Amal's  LOG  ========="
cat  amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat  basim/logBasim.txt
echo
echo

echo "=============================="
echo "Verifying the File Unencrypted Transmission"
echo
diff -s bunny.mp4    bunny.cpy
echo
