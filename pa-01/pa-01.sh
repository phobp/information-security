#!/bin/bash
echo
echo "Script to run Programming Assignment #1"
echo "By: Mohamed Aboutabl"
echo "Edited by: Brendan Pho and Wesley Llamas"
echo

rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt basim/bunny.mp4 

echo "=============================="
echo "Compiling all source"
	gcc genkey.c                    -o genkey       -lcrypto
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher

echo
./genkey

echo "This is the symmetric Key material:"
hexdump -v -C key.bin
echo

echo "This is the IV material:"
hexdump -v -C iv.bin

echo
echo "Sharing the key and IV with Amal and Basim"

echo "=============================="
echo "Starting the dispatcher"
./dispatcher 

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo
echo

echo "=============================="
echo "Verifying File Encryption / Decryption"
echo
diff -s bunny.mp4 bunny.decr
echo
