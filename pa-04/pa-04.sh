#!/bin/bash
echo
echo "Script to run PA-04"
echo "By: Mohamed Aboutabl"
echo

rm -f dispatcher   kdc/kdc  kdc/logKDC.txt   amal/amal   amal/logAmal.txt 
rm -f basim/basim  basim/logBasim.txt 
rm -f bunny.mp4    bunnyCopy.mp4
ln -s  ../bunny.mp4       bunny.mp4

echo "=============================="
echo "Compiling all source"
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -l:libcrypto.so.1.1
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -l:libcrypto.so.1.1
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -l:libcrypto.so.1.1
	gcc wrappers.c     dispatcher.c -o dispatcher

echo "=============================="
echo "Starting the Dispatcher"
./dispatcher

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo

echo
echo "======  The KDC's  LOG  ========="
cat kdc/logKDC.txt
echo
echo

