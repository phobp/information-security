/*----------------------------------------------------------------------------
FILE:   basim.c

Written By: 
     1- Dr. Mohamed Aboutabl
     2- Brendan Pho and Wesley Llamas (GROUP 7)
 
Submitted on: September 16, 2019

This code complies with the JMU Honor Code.
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{
    int       fd_out , fd_ctrl , fd_data , fd_ctrlSend ;
    FILE     *log ;
    BIGNUM   *x, *max, *prime, *prmtvRoot;
    uint8_t key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned key_len = 32; // i.e. 256 bits 
    unsigned iv_len = 16; // i.e. 128 bits   

    int plaintext;
    int status = 0;

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if( argc < 4 )
    {
        printf("Missing command-line arguments: %s <recv ctrlFD> <recv dataFD> <send ctrlFD\n" , argv[0]) ;
        exit(-1) ;
    }
    fd_ctrl     = atoi( argv[1] ) ;
    fd_data     = atoi( argv[2] ) ;
    fd_ctrlSend = atoi( argv[3] ) ;

    log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }
    //fprintf( log , "This is Basim. Will receive CTRL from FD %d, data from FD %d, and send CTRL to FD  %d\n" ,
    //               fd_ctrl , fd_data, fd_ctrlSend );

    fprintf( log , "This is Basim. Will send encrypted data to FD %d\n" , fd_data );

    // Get the session symmetric key
    int fd_key, fd_iv;
    fd_key = open("key.bin", O_RDONLY);
    if (fd_key == -1) {
        fprintf(stderr, "\nBasim: Could not open key.bin\n");
        fclose(log);
        exit(-1);
    }
   
    read(fd_key, key, key_len);   
    fprintf(log, "\nUsing this symmetric key of length %d bytes\n", key_len);     
    BIO_dump_fp(log, (const char*)key, key_len);
    close(fd_key);
   
    // Get the session Initial Vector 
    fd_iv = open("iv.bin", O_RDONLY);
    if (fd_iv == -1) {
    fprintf(stderr, "\nBasim: Could not open iv.bin\n");
    fclose(log); exit(-1);
    }
   
    read(fd_iv, iv, iv_len);
    fprintf(log, "\nUsing this Initial Vector of length %d bytes\n", iv_len);
    BIO_dump_fp(log, (const char*) iv, iv_len);
    close(fd_iv);

    fd_out = open("bunny.decr" , O_WRONLY | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR );
    if ( fd_out == - 1 ) {
        fprintf( stderr , "\nBasim: Could not open bunny.decr\n");
        fclose(log);
        exit(-1);
    }

    plaintext = decryptFile( fd_data , fd_out , key , iv );
    printf("\nBasim terminated ... with status =%d\n" , status );

    EVP_cleanup();
    ERR_free_strings();
    fclose( log ) ;  

    return 0 ;
}

