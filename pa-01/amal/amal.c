/*----------------------------------------------------------------------------
FILE:   amal.c

Written By: 
     1- Dr. Mohamed Aboutabl
     2- Brendan Pho and Wesley Llamas (GROUP 7)
 
Submitted on: September 16, 2019

This code complies with the JMU Honor Code.
----------------------------------------------------------------------------*/

#include "../myCrypto.h"
#include <linux/random.h>

int main ( int argc , char * argv[] )
{
    uint8_t key[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH];
    unsigned key_len = 32 ; //i.e. 256 bits
    unsigned iv_len = 16 ; // i.e. 128 bits
    unsigned  bnSize ; 
    uint8_t   digest[EVP_MAX_MD_SIZE] ;
    int       fd_in , fd_ctrl , fd_data , fd_ctrlRcv ;
    FILE     *log ;
    BIGNUM   *prime , *prmtvRoot , *x , *r , *s ;
    BN_CTX   *ctx; /* used internally by the bignum lib */

    int status = 0;
    int ciphertext;
   
    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Check for missing command line arguments
    if( argc < 4 )
    {
        printf("Missing command-line arguments: %s <send ctrlFD> <send dataFD> <recv ctrlFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_ctrl    = atoi( argv[1] ) ;
    fd_data    = atoi( argv[2] ) ;
    fd_ctrlRcv = atoi( argv[3] ) ;

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Amal. Could not create log file\n");
        exit(-1) ;
    }
        
    fprintf( log , "This is Amal. Will send encrypted data to FD %d\n" , fd_data );
    fflush( log ) ;
    
    // Get the session symmetric key
    int fd_key , fd_iv, fd_bunny;
    fd_key = open("key.bin", O_RDONLY );
    if (fd_key == -1) {
        fprintf(stderr , "\nAmal: Could not open key.bin\n");
        fclose(log); exit(-1);
    }
        
    read (fd_key, key, key_len);
    fprintf(log, "\nUsing this symmetric key of length %d bytes\n", key_len);
    BIO_dump_fp(log, (const char*) key, key_len);
    close(fd_key);
        
    // Get the session Initial Vector 
    fd_iv = open("iv.bin", O_RDONLY);
    if (fd_iv == -1) {
        fprintf(stderr, "\nAmal: Could not open iv.bin\n");
        fclose(log); exit(-1);
    }

    read(fd_iv, iv, iv_len);
    fprintf(log, "\nUsing this Initial Vector of length %d bytes\n", iv_len);
    BIO_dump_fp(log, (const char*) iv, iv_len);
    close(fd_iv);

    // Open the mp4 file
    fd_in = open("bunny.mp4", O_RDONLY);
    if (fd_in == -1 ) {
        fprintf(stderr, "\nAmal: Could not open bunny.mp4\n");
        fclose(log); exit(-1);
    }

    ciphertext = encryptFile( fd_in , fd_data , key , iv );

    printf("\nAmal terminated ... with status =%d\n" , status );
    
    EVP_cleanup();
    ERR_free_strings();

    fclose( log );  

    return 0;
}

