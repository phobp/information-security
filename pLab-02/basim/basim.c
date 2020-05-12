/*----------------------------------------------------------------------------
pLAB-02   Key Exchange using Public-Key Encryption

Written By:  1- Brendan Pho
             2- Wesley Llamas

Submitted on: 9/19/2019 
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
    RSA      *rsa_privK = NULL ;
    // key & IV for symmetric encryption of data
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    char     *decryptedFile  = "bunny.decr" ;
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

    fprintf(log, "This is Basim. Will receive encrypted data from FD %d and session key/IV from FD %d\n", fd_data, fd_ctrl);
    rsa_privK = getRSAfromFile( "basim/basim_priv_key.pem", 0 ) ;
    fflush(log);
    // Allocate memory to receive the encrypted session key
    int encrKey_len = RSA_size( rsa_privK ) ;
    uint8_t *encryptedKey = malloc( encrKey_len ) ;  
 
    // Now read the encrypted session key and the IV from the Control Pipe 
    if(read(fd_ctrl, encryptedKey, encrKey_len) != encrKey_len) {
        handleErrors("Failed to read file\n");
    }

    if(read(fd_ctrl, iv, INITVECTOR_LEN) != INITVECTOR_LEN) {
        handleErrors("Failed to read file\n");
    }
   
    // Now, decrypt the session key using Basim's private key
    // Using RSA_PKCS1_PADDING padding, which is the currently recommended mode.
    int sessionKey_len = 
        RSA_private_decrypt( encrKey_len , encryptedKey, sessionKey , rsa_privK 
                             , RSA_PKCS1_PADDING );

    // Dump the session key and IV to the Log
    fprintf(log, "\nUsing this symmetric session key of length %d bytes\n", sessionKey_len);
    fflush(log);
    BIO_dump_fp(log, (const char*)sessionKey, sessionKey_len);
    fflush(log);

    fprintf(log, "\nUsing this Initial Vector of length %d bytes\n", INITVECTOR_LEN);
    fflush(log);
    BIO_dump_fp(log, (const char*)iv, INITVECTOR_LEN);
    fflush( log );

    /* Finally, decrypt the ciphertext file using the symmetric session key */
    decryptFile(fd_data, fd_decr, sessionKey, iv);
    
    // Close any open files / descriptors
    close(fd_ctrl);
    close(fd_data);
    close(fd_decr); 
    fclose(log);
    free(encryptedKey);
        
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();   
}

