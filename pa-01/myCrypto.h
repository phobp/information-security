/*----------------------------------------------------------------------------
Written By: 
     1- Dr. Mohamed Aboutabl
Submitted on: 
----------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <linux/random.h>
#include <assert.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

void    handleErrors( char *msg) ;
unsigned encryptFile(int fd_in, int fd_out, unsigned char *key, unsigned char *iv) ;
unsigned decryptFile(int fd_in, int fd_out, unsigned char *key, unsigned char *iv) ;

