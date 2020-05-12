/*----------------------------------------------------------------------------
My Cryptographic Library

FILE:   myCrypto.c

Written By:  1- Brendan Pho
             2- Wesley Llamas

Submitted on: 9/19/2019 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

//***********************************************************************
// pLAB-01
//***********************************************************************

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    exit(-1);
}

//-----------------------------------------------------------------------------
// Encrypt the plaint text stored at 'pPlainText' into the 
// caller-allocated memory at 'pCipherText'
// Caller must allocate sufficient memory for the cipher text
// Returns size of the cipher text in bytes

// For the following Encryption/Decryption, 
// use a 256-bit key and AES in CBC mode (with a 128-bit IV)
// Ensure the (key,IV) being used match the specified algorithm

unsigned encrypt( uint8_t *pPlainText, unsigned plainText_len, 
             uint8_t *key, uint8_t *iv, uint8_t *pCipherText )
{
    int status;
    unsigned len = 0, encryptedLen = 0;
    
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();   
    if (!ctx)   
        handleErrors("encrypt: failed to creat CTX");
   
    // Initialise the encryption operation.
    status = EVP_EncryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptInit_ex");
   
    // Call EncryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular encryption
    status = EVP_EncryptUpdate(ctx, pCipherText, &len, pPlainText, plainText_len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptUpdate");
        encryptedLen += len;
   
    // If additional ciphertext may still be generated,
    // the pCipherText pointer must be first advanced forward
    pCipherText += len;
   
    // Finalize the encryption. 
    status = EVP_EncryptFinal_ex(ctx, pCipherText, &len);
    if (status != 1)
        handleErrors("encrypt: failed to EncryptFinal_ex");
    encryptedLen += len; // len could be 0 if no additional cipher text was generated
   
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return encryptedLen;      
}

//-----------------------------------------------------------------------------
// Decrypt the cipher text stored at 'pCipherText' into the 
// caller-allocated memory at 'pDecryptedText'
// Caller must allocate sufficient memory for the decrypted text
// Returns size of the decrypted text in bytes

unsigned decrypt( uint8_t *pCipherText, unsigned cipherText_len, 
                  uint8_t *key, uint8_t *iv, uint8_t *pDecryptedText)
{
    int status;
    unsigned len = 0, decryptedLen = 0;
   
    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors("decrypt: failed to creat CTX");
    
    // Initialise the decryption operation.
    status = EVP_DecryptInit_ex(ctx, ALGORITHM(), NULL, key, iv);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptInit_ex");
   
    // Call DecryptUpdate as many times as needed (e.g. inside a loop)
    // to perform regular decryption
    status = EVP_DecryptUpdate(ctx, pDecryptedText, &len, pCipherText, cipherText_len);
    if (status != 1)
        handleErrors("decrypt: failed to DecryptUpdate");
    decryptedLen += len;
   
    // If additionl decrypted text may still be generated,
    // the pDecryptedText pointer must be first advanced forward
    pDecryptedText += len;
   
    // Finalize the decryption. 
    status = EVP_DecryptFinal_ex(ctx, pDecryptedText, &len);   
    if (status != 1)
        handleErrors("decrypt: failed to DecryptFinal_ex");
    decryptedLen += len;
   
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
   
    return decryptedLen;
}

//***********************************************************************
// PA-01
//***********************************************************************

int encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
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

//-----------------------------------------------------------------------------
int decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
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

//***********************************************************************
// pLAB-02
//***********************************************************************

RSA *getRSAfromFile(char * filename, int public)
{
    RSA *rsa = RSA_new();
    // open the binary file whose name if 'filename' for reading
    // Create a new RSA object using RSA_new() ;
    // To read a public RSA key, use PEM_read_RSA_PUBKEY()
    // To read a public RSA key, use PEM_read_RSAPrivateKey()
    // close the binary file 'filename'
    
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file %s.", filename);
        exit(-1);
    }

    if (public) {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    }
    fclose(fp);
    return rsa;
}

//-----------------------------------------------------------------------------
