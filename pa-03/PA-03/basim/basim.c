/*----------------------------------------------------------------------------
PA-02   Key Exchange using Public-Key Encryption

Written By:  1- Brendan Pho
             2- Wesley Llamas

Submitted on: 8/6/2019 
----------------------------------------------------------------------------*/
/*
    I am Basim. I will decrypt a file from Amal.
    She exchanged the session key with me encrypted using my public key.

    Adapted from:
        http://hayageek.com/rsa-encryption-decryption-openssl-c/
*/

#include "../myCrypto.h"

// Always check for possible failures AND Free any dynamic memory you allocated 
// to avoid losing points

void main( int argc , char * argv[] ) 
{   
    RSA      *rsa_pubK = NULL ;
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    char     *decryptedFile  = "bunnyCopy.mp4" ;
    int      fd_decr , fd_ctrl , fd_data ;

    uint8_t digest[32];
    size_t hashSize;

    // Get AtoB Control and Data file descriptor from the argv[]
    fd_ctrl     = atoi( argv[1] );
    fd_data     = atoi( argv[2] );

    // Open Log File
    FILE *log = fopen("basim/logBasim.txt" , "w");
    if (!log) {
        fprintf(stderr, "This is Basim. Could not open log file\n");
        exit(-1);
    }

    // Save a copy of the bunny.mp4 file in the PA-03 folder
    FILE *decr = fopen( decryptedFile , "w");
    if(!decr < 0) {
        fprintf(stderr, "This is Basim. Could not open decrypt file\n");
        exit(-1);
    }

    fd_decr = fileno(decr);

    fprintf(log, "This is Basim. Will receive CTRL from FD %d, data from FD %d\n", fd_ctrl, fd_data);
    fflush( log );

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = NULL;
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    

    // Get the DH parameters sent by Amal over the AtoB Control pipe
    const BIGNUM *pp, *y, *gg, *qq;

    fprintf(log, "\nBasim: Received these parameters (in Hex) from Amal\n");
    
    pp = BN_read_fd(fd_ctrl);
    fprintf(log, "    Prime\t : ");
    BN_print_fp(log, pp);

    gg = BN_read_fd(fd_ctrl);
    fprintf(log, "\n    Root\t : ");
    BN_print_fp(log, gg);

    y = BN_read_fd(fd_ctrl);
    fprintf(log, "\n    Public value : ");
    BN_print_fp(log, y);
    fprintf(log, "\n");

    // Call fileDigest() to receive the incoming data over AtoB data pipe
    // Compute the hash value
    hashSize = fileDigest(fd_data, digest, fd_decr);


    fprintf(log, "\nBasim: Starting to receive incoming file and compute its digest\n");

    fprintf(log, "\nBasim: Here is the locally-computed digest of the incoming file:\n");
    BIO_dump_fp(log, (const char *) digest, 32);

    fprintf( log , "\nBasim: Received this Elgamal signature from Amal:\n" );


    fprintf( log , "    r : ");
    r =  BN_read_fd(fd_ctrl);
    BN_print_fp(log, r);
    fflush(log);

    fprintf( log , "\n    s : " );
    s =  BN_read_fd(fd_ctrl);
    BN_print_fp(log, s);
    fflush(log);

    // Verify Amal's signature by invoking the elgamalValidate() function.
    fprintf(log , "\n\nBasim: This Elgamal signature is .... ");

    int validation = elgamalValidate( digest , 32 , pp , gg , y , r , s , ctx );

    if ( validation == 1 ) {
        fprintf( log , "VALID\n");
    } else {
        fprintf( log , "INVALID\n");
    }

    fprintf( log , "\n");

    
    // Close any open files / descriptors
    close(fd_decr);
    fclose(log);

    BN_free((BIGNUM *) pp);
    BN_free((BIGNUM *) gg);
    BN_free((BIGNUM *) y);
    BN_free(x);
    BN_free(r);
    BN_free(s);
    BN_CTX_free(ctx);

   
}

