/*----------------------------------------------------------------------------
pLAB-02   Key Exchange using Public-Key Encryption

Written By:  1- Brendan Pho 
             2- Wesley Llamas

             Submitted on: 9/19/2019 
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
    RSA  *rsa_pubK = NULL  ;
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
        exit(-1);
   }
    
    fprintf(log, "This is Amal. Will send encrypted data to FD %d and session key/IV to FD %d\n" , fd_data, fd_ctrl);
        rsa_pubK  =  getRSAfromFile( "amal/basim_pub_key.pem", 1 );

    // Generate a random session key , and an IV then dump them to Log file
    RAND_bytes(sessionKey, SYMMETRIC_KEY_LEN);
    RAND_bytes(iv, INITVECTOR_LEN);
    
    fprintf(log, "\nUsing this symmetric session key of length %d bytes\n", SYMMETRIC_KEY_LEN);
    BIO_dump_fp(log, (const char*)sessionKey, SYMMETRIC_KEY_LEN);

    fprintf(log, "\nUsing this Initial Vector of length %d bytes\n", INITVECTOR_LEN);
    BIO_dump_fp(log, (const char*)iv, INITVECTOR_LEN);
    fflush( log );

    // Encrypt the session key using Basim's Public Key
    uint8_t *encryptedKey = malloc( RSA_size( rsa_pubK ) ) ;  

    // Using RSA_PKCS1_PADDING padding, which is the currently recommended mode.
    int encrKey_len  
        = RSA_public_encrypt( SYMMETRIC_KEY_LEN, sessionKey, encryptedKey, rsa_pubK 
                              , RSA_PKCS1_PADDING );
     
    // Send the encrypted session key, and  the IV to the AtoB Control Pipe 
    write(fd_ctrl, encryptedKey, encrKey_len);
    write(fd_ctrl, iv, INITVECTOR_LEN);

    /* Finally, encrypt the plaintext file using the symmetric session key */
    encryptFile(fd_plain, fd_data, sessionKey, iv);

    // Close any open files / descriptors
    fclose(log);
    close(fd_plain);
    close(fd_data);
    close(fd_ctrl);
    free(encryptedKey);

    // Clean up the crypto library
    RSA_free( rsa_pubK  ) ;
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();
}

