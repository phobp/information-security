/*----------------------------------------------------------------------------
PA-02   Key Exchange using Public-Key Encryption

Written By:  1- Brendan Pho
             2- Wesley Llamas

Submitted on: 10/6/2019 
----------------------------------------------------------------------------*/
/*
    I am Basim. I will decncrypt a file from Amal.
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
    // key & IV for symmetric encryption of data
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    char     *decryptedFile  = "bunny.cpy" ;
    int      fd_decr , fd_ctrl , fd_data ;
     
    // Initialize the crypto library
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();

    // Get AtoB Control and Data file descriptor from the argv[]
    // Open Log File
    // Open Decrypted Output File
    // Get my RSA Private key generated outside this program using the openssl tool 
    fd_ctrl     = atoi( argv[1] );
    fd_data     = atoi( argv[2] );

    FILE *log = fopen("basim/logBasim.txt" , "w");
    if (!log) {
        fprintf(stderr, "This is Basim. Could not open log file\n");
        exit(-1);
    }

    fd_decr = open(decryptedFile, O_CREAT|O_WRONLY, 0666);
    if(fd_decr < 0) {
        fprintf(stderr, "This is Basim. Could not open decrypt file\n");
        exit(-1);
    }

    fprintf(log, "This is Basim. Will receive digest from FD %d and file from FD %d\n", fd_ctrl, fd_data);
    rsa_pubK = getRSAfromFile( "basim/amal_pub_key.pem", 1 ) ;
    fflush(log);
    // Allocate memory for the signature
    int signature_len = RSA_size( rsa_pubK ) ;
    uint8_t *signature = malloc(signature_len);
    uint8_t digest_rec[32];
    uint8_t digest_calc[32];
 
    fprintf(log, "This is Basim. Starting to receive incoming file and compute its digest\n");
    size_t digest_size = fileDigest(fd_data, digest_calc, fd_decr);
    read(fd_ctrl, signature, signature_len);
    int digest_rec_len = RSA_public_decrypt(signature_len, signature, digest_rec, rsa_pubK, RSA_PKCS1_PADDING);
   
    FILE *digest_file = fopen("basim/digest.bin", "w");
    if (!digest_file) {
        printf("Could not make digest file.\n");
    }

    FILE *signature_file = fopen("basim/signature.bin", "w");
    if (!signature_file) {
        printf("Could not make signature file.\n");
    }

    fwrite(digest_calc, digest_size, 1, digest_file);
    fwrite(signature, signature_len, 1, signature_file);
    fclose(digest_file);
    fclose(signature_file);
    digest_file = fopen("basim/decryptedSignature.bin", "w");
    fwrite(digest_rec, digest_rec_len, 1, digest_file);
    fclose(digest_file);
    

    // Dump the digest and signature to the Log
    fprintf(log, "\nThis is Basim. Here is my locally-computed the digest of the incoming file:\n");
    BIO_dump_fp(log, digest_calc, digest_size);

    fprintf(log, "\nThis is Basim. I received the following signature from Amal:\n");   
    BIO_dump_fp(log, signature, signature_len);

    fprintf(log, "\nThis is Basim. Here is Amal's decrypted signature:\n");
    BIO_dump_fp(log, digest_rec, digest_rec_len);
    fflush( log );
    
    int compare_value;
    if (!(compare_value = memcmp(digest_calc, digest_rec, 256/8))) {
        fprintf(log, "\n\nThis is Basim. Amal's signature is VALID.\n");
    }
    
    // Close any open files / descriptors
    close(fd_ctrl);
    close(fd_data);
    close(fd_decr); 
    fclose(log);
    free(signature);
    RSA_free(rsa_pubK);
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();   
}

