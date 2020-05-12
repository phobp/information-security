/*----------------------------------------------------------------------------

FILE:   myCrypto.c

Written By: 
     1- Dr. Mohamed Aboutabl
     2- Brendan Pho and Wesley Llamas (GROUP 7)
 
Submitted on: September 16, 2019

This code complies with the JMU Honor Code.
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

unsigned encryptFile(int fd_in, int fd_out, unsigned char *key, unsigned char *iv)
{
    int status;
    unsigned char plaintext_buf [1008];
    unsigned char ciphertext_buf [1024];
    int len = 0, encryptedLen = 0;
    int read_plaintext = 1;
    
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();   
    if (!ctx)   
        handleErrors("encrypt: failed to creat CTX");
   
    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");
   
    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    while (read_plaintext != 0) {
        read_plaintext = read(fd_in, plaintext_buf , 1008);
        status = EVP_EncryptUpdate(ctx, ciphertext_buf, &len, plaintext_buf, read_plaintext);
        if (status != 1) 
            handleErrors("encrypt: failed to EncryptUpdate");
            
        encryptedLen += len;
        write(fd_out, ciphertext_buf, len);
    }
   
    // Finalize the encryption
    status = EVP_EncryptFinal_ex(ctx, ciphertext_buf, &len);
    
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len;

    write(fd_out, ciphertext_buf, len);
   
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return encryptedLen;
}

unsigned decryptFile(int fd_in, int fd_out, unsigned char *key, unsigned char *iv)
{
    int status;
    unsigned char plaintext_buf [1008];
    unsigned char ciphertext_buf [1024];
    int len = 0, decryptedLen = 0;
    int read_plaintext = 1;
   
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("decrypt: failed to creat CTX");
    
    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");
   
    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    while (read_plaintext != 0 ) {
        read_plaintext = read(fd_in, ciphertext_buf, 1024);  
        status = EVP_DecryptUpdate(ctx, plaintext_buf, &len, ciphertext_buf, read_plaintext);
        if (status != 1)
            handleErrors("decrypt: failed to DecryptUpdate");
        decryptedLen += len;
        write(fd_out, plaintext_buf, len);
    }
   
    // Finalize the decryption. 
    status = EVP_DecryptFinal_ex(ctx, plaintext_buf, &len);   
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;
    write(fd_out, plaintext_buf, len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
   
    return decryptedLen;
}

