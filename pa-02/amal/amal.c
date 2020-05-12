/*----------------------------------------------------------------------------
PA-02   Key Exchange using Public-Key Encryption

Written By:  1- Brendan Pho 
             2- Wesley Llamas

             Submitted on: 10101010101010101010/6/2019 
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
    
    // Initialize the crypto library
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    // Get AtoB Control and Data file descriptor from the argv[]
    // Open Log File
    // Open Plaintext File
    // Get Basim's RSA Public key generated outside this program by the opessl tool 
    fd_ctrl     = atoi( argv[1] );
    fd_data     = atoi( argv[2] );

    FILE *log = fopen("amal/logAmal.txt" , "w"); 
    if (!log) {
        fprintf(stderr, "This is Amal. Could not create log file\n");
        exit(-1);
    }
   
   fd_plain = open(plaintextFile, O_RDONLY);
   if (fd_plain < 0) {
        fprintf(stderr, "This is Amal. Could not open plaintext file.\n");
        exit(1);
   }
    
    uint8_t digest[32];
    rsa_privK = getRSAfromFile("amal/amal_priv_key.pem", 0);
    uint8_t *signature = malloc(RSA_size(rsa_privK));
    
    fprintf(log, "This is Amal. Will send digest to FD %d and file to FD %d\n", fd_ctrl, fd_data);
    fprintf(log, "This is Amal. Starting to digest the input file.\n");
    fflush(log);
    
    size_t digest_size = fileDigest(fd_plain, digest, fd_data);

    FILE* digest_file = fopen("amal/digest.bin","w");
    if (!digest_file) {
        printf("Could not create digest file.\n");
        exit(1);
    }

    fwrite(digest, digest_size, 1, digest_file);
    fclose(digest_file);

    int signature_len = RSA_private_encrypt(digest_size, digest, signature, rsa_privK, RSA_PKCS1_PADDING);

    write(fd_ctrl, signature, signature_len);

    FILE* signature_file = fopen("amal/signature.bin", "w+");
    if (!signature_file) {
        printf("Could not create digest file.\n");
        exit(1);
    }

    fwrite(signature, signature_len, 1, signature_file);
    fclose(signature_file); 
    fflush(log);

    fprintf(log, "\nThis is Amal. Here is the digest of the file:\n");
    BIO_dump_fp(log, digest, digest_size);
    fflush(log);

    fprintf(log, "\nThis is Amal. Here is my signature on the file:\n");
    BIO_dump_fp(log, signature, signature_len);
    fflush(log);

    // Close any open files / descriptors
    fclose(log);
    close(fd_plain);
    close(fd_data);
    close(fd_ctrl);
    free(signature);

    // Clean up the crypto library
    RSA_free( rsa_privK  ) ;
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();
}

