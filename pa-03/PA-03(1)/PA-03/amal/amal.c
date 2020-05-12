/*----------------------------------------------------------------------------
PA-02   Key Exchange using Public-Key Encryption

Written By:  1- Brendan Pho 
             2- Wesley Llamas

             Submitted on: 8/6/2019 
----------------------------------------------------------------------------*/
/*
    I am Amal. I will encrypt a large file to Basim.
    I will exchange the session key with Basim encrypted using his RSA public key.

    Adapted from:
        http://hayageek.com/rsa-encryption-decryption-openssl-c/
*/

#include "../myCrypto.h"

// Always check for possible failures AND Free any dynamic memory you allocated 
// to avoid losing points

void main( int argc , char * argv[] ) 
{    
    RSA  *rsa_privK = NULL  ;
    // key & IV for symmetric encryption of data
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    char     *plaintextFile  = "bunny.mp4" ;
    int      fd_plain , fd_ctrl , fd_data ;

    uint8_t digest[32];

    // Get AtoB Control and Data file descriptor from the argv[]
    fd_ctrl     = atoi( argv[1] );
    fd_data     = atoi( argv[2] );

    // Open Log File
    FILE *log = fopen("amal/logAmal.txt" , "w"); 
    if (!log) {
        fprintf(stderr, "This is Amal. Could not create log file\n");
        exit(-1);
    }
   
    fprintf(log, "This is Amal. Will send CTRL to FD %d, Data to FD %d\n", fd_ctrl, fd_data);
    fflush(log);

    fprintf( log, "\nThis is Amal. Here are my parameters (in Hex) :\n" );

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x = NULL;
    BIGNUM *y = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
 
    const BIGNUM *dh_p, *dh_q, *dh_g;

    DH *dh = DH_new();
 
    // Generate 512-bit prime number whose primitive root is equal to 2
    DH_generate_parameters_ex(dh, 512, 2, NULL);
    DH_get0_pqg(dh, &dh_p, &dh_q, &dh_g);

    fprintf(log, "    Prime\t : ");
    BN_print_fp(log, dh_p);
 
    if( BN_is_prime_ex(dh_p, BN_prime_checks, ctx, NULL) ) {
        fprintf(log, "\n    It is indeed prime");
    } else {
        fprintf(log, "\n    It is not prime");
        exit(-1);
    }

    fprintf(log, "\n    Root\t : ");
    BN_print_fp(log, dh_g);
    fflush( log ); 
    
    // Randomly selects a private value x and computes the corresponding public value y
    x = BN_myRandom(dh_p);
 
    // Let y = gen^x mod prime
    BN_mod_exp( y, dh_g, x, dh_p, ctx );
 
    fprintf(log, "\n    Private value: ");
    BN_print_fp(log, x);
    fflush( log ); 

    fprintf(log, "\n    Public value : ");
    BN_print_fp(log, y);
    fflush( log );
 
    fprintf(log, "\n\nAmal: sending prime, root, and public value to Basim\n\n");
    fflush( log );

    // Share values with Basim over AtoB Control pipe
    BN_write_fd( dh_p , fd_ctrl );
    BN_write_fd( dh_g , fd_ctrl );
    BN_write_fd( y , fd_ctrl );

    // Open Plaintext File (bunny.mp4)
    fd_plain  = open( plaintextFile, O_RDONLY );
    if ( fd_plain < 0 ) {
        fprintf(stderr, "\nAmal: Could not open bunny.mp4\n");
        fclose(log);
    }

    fprintf(log, "Amal: Successfully opened the data file\n");
    fprintf(log, "Amal: Starting to digest the input file\n");
    fflush( log ); 

    // Compute sha256 hash value of the file
    // Transmit copy of the file over the AtoB Data pipe
    size_t hashSize = fileDigest( fd_plain , digest, fd_data ); // method returns size_t

    fprintf(log, "\nAmal: Here is my digest of the file:\n");
    BIO_dump_fp( log , (const char*) digest , 32 );
    fflush( log ); 

    fprintf( log , "\nAmal: Generating the Elgamal Signature" );
    fflush( log );
 
    // Use Amal's DH parameters computed in steps 1 and 2 to digitally sign the digest computed
    // in step 4. 
    elgamalSign( digest, 32 , dh_p, dh_g, x, r, s, ctx );
 
    fprintf(log, "\n    r : ");
    BN_print_fp(log, r);
    fflush( log ); 
 
    fprintf(log, "\n    s : ");
    BN_print_fp(log, s);
    fprintf(log, "\n");
    fflush( log );

    // Transmits Amal's digital signature to Basim over the AtoB Control pipe.  
    BN_write_fd(r, fd_ctrl);
    BN_write_fd(s, fd_ctrl);

    BN_free( (BIGNUM *) dh_p );
    BN_free((BIGNUM *) dh_g );
    BN_free( (BIGNUM *) dh_q );
    BN_free(x);
    BN_free(y);
    BN_free(r);
    BN_free(s);
    BN_CTX_free(ctx); 

    fclose(log);
    close( fd_plain );

}

