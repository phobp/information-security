/*----------------------------------------------------------------------------
BigNum Demo:

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

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

void DH_get0_pqg(const DH *dh,const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);


void    handleErrors( char *msg) ;
RSA    *getRSAfromFile(char * filename, int public) ;
size_t  fileDigest( int fd_in , uint8_t *digest , int fd_save) ;
int     BN_write_fd( int fd_out , BIGNUM *bn ) ;
BIGNUM *BN_read_fd( int fd_in ) ;
BIGNUM * BN_myRandom( BIGNUM *p ) ;
