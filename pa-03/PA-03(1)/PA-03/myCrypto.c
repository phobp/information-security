/*----------------------------------------------------------------------------
PA-03  Big Integers & Elgamal Digital Signature

 FILE: myCrypto.c

Written By:  1- Brendan Pho
             2- Wesley Llamas

Submitted on: October 30, 2019
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

size_t fileDigest(int fd_in, uint8_t *digest, int fd_out)
{
    int status;
    uint8_t *buff[PLAINTEXT_LEN_MAX];
    unsigned int mdLength;
    int readIn = 0;
    int writeOut = 0;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        handleErrors("Message digest context could not be created.\n");
    }

    status = EVP_DigestInit(mdctx, EVP_sha256());
    if (status != 1) {
        handleErrors("Message digest context could not be initialized.\n");
    }

    while((readIn = read(fd_in, buff, PLAINTEXT_LEN_MAX)) > 0)
    {
        status = EVP_DigestUpdate(mdctx, buff, readIn);
        if (status != 1) {
            handleErrors("DigestUpdate could not digest.\n");
        }

        writeOut = write(fd_out, buff, readIn);
        if (writeOut != readIn) {
            handleErrors("Plaintext is not being correctly outputted to the file descriptor.\n");
        }
    }

    EVP_DigestFinal(mdctx, digest, &mdLength);
    return mdLength;

}

//***********************************************************************
// PA-03
//***********************************************************************

int BN_write_fd( const BIGNUM *bn , int fd_out ) {

    // Sends the # of bytes, followed by the bytes themselves of a BIGNUM's value to file descriptor fd_out
    // Returns 1 on succes, 0 on failure

    unsigned num_bytes = 0;
    num_bytes = BN_num_bytes( bn );

    write( fd_out , &num_bytes , sizeof( unsigned ) );

    unsigned char *bnWrite = malloc( num_bytes );
    BN_bn2bin( bn , bnWrite );

    if( write( fd_out , bnWrite , num_bytes ) < 0 ) {
        printf("Failed to write big number.\n");
        return 0;
    }   

    return 1;

}

BIGNUM *BN_read_fd( int fd_in ) {
    
    // Read the # of bytes, then the bytes themselves of a BIGNUM's value from the file descriptor fd_in
    // Returns: a newly-created BIGNUM, which should be freed later by the caller
    //      NULL on failure

    BIGNUM *bnCopy = BN_new();

    unsigned num_bytes = 0;
    read( fd_in , &num_bytes , sizeof( unsigned ) );
    unsigned char *bnWrite = malloc( num_bytes );

    int read_fd = read( fd_in , bnWrite, num_bytes );
    BN_bin2bn( bnWrite , num_bytes, bnCopy );
    
    if ( read_fd < 0 ) {
        printf("Failed to read big number.\n");
        return NULL;
    }

    return bnCopy;
}

BIGNUM *BN_myRandom( const BIGNUM *p ) {

    // Returns a newly created random BIGNUM such that: 1 < BN's value < (p-1)

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *random = BN_new();
    BIGNUM *pBn = BN_new();
    BIGNUM *modRandom = BN_new();

    pBn = BN_dup( p );

    BIGNUM *one = BN_new();
    BN_dec2bn( &one , "1" );
    BN_sub( pBn , pBn, one );
    BN_rand_range( random , pBn );

    BN_sub( pBn , pBn , one ); // Caclulation of (p-1)
    BN_mod( modRandom , random , pBn , ctx );

    BN_CTX_free( ctx );
    BN_free( random );
    BN_free( pBn );
    BN_free( one );

    return modRandom;

}

void elgamalSign( const uint8_t *digest , int len , const BIGNUM *q , const BIGNUM *gen , const BIGNUM *x , BIGNUM *r , BIGNUM *s , BN_CTX *ctx ) {

    // Use the prime 'q', the primitive root 'gen', and the private 'x'
    // to compute the Elgamal signature (r, s) on the 'len'-byte long 'digest'

    BIGNUM *temp = BN_new();
    BIGNUM *k = BN_new();
    BIGNUM *kInv = BN_new();
    BIGNUM *mA = BN_new();
    BIGNUM *xMultR = BN_new();
    BIGNUM *tempRandom = BN_new();

    BN_copy( tempRandom , q );
    
    // Choose random secret k between 1 and q-1
    k = BN_myRandom(q);

    tempRandom = BN_dup( q );

    BIGNUM *one = BN_new();
    BN_dec2bn( &one , "1" );

    // q-1
    BN_sub(tempRandom, tempRandom, one);

    while ( BN_is_one( temp ) == 0 ) {
        k = BN_myRandom( q );
        BN_gcd( temp , k , tempRandom , ctx );
    }

    // Let r = gen^k mod q
    BN_mod_exp( r , gen , k , q , ctx );

    // k^-1 mod q-1
    BN_mod_inverse(kInv, k, tempRandom, ctx);

    BN_bin2bn( digest , len , mA );

    // x * r
    BN_mul(xMultR, x, r, ctx);

    // (mA - x*r)
    BN_sub(mA, mA, xMultR);

    // k^-1 * (mA - x*r) mod (q - 1)
    BN_mod_mul(s, kInv, mA, q, ctx);

    BN_free(temp);
    BN_free(k);
    BN_free(kInv);
    BN_free(mA);
    BN_free(xMultR);
    BN_free(tempRandom);
    BN_free(one);

}

int elgamalValidate( const uint8_t *digest , int len , const BIGNUM *q , const BIGNUM *gen , const BIGNUM *y , BIGNUM *r , BIGNUM *s , BN_CTX *ctx ) {

    // Use the prime 'q', the primitive root 'gen', and the public 'y'
    // to validate the Elgamal signature (r, s) on the 'len'-byte long 'digest'
    // Return 1 if valid, 0 otherwise

    // Verify that 1 < r < q-1

    int valid = 0;
    BIGNUM *v1 = BN_new();
    BIGNUM *v2 = BN_new(); 
    BIGNUM *mB = BN_new(); // mB
    BIGNUM *yR = BN_new(); //xmultr
    BIGNUM *rS = BN_new();
    BIGNUM *qBn = BN_new(); //temprand

    qBn = BN_dup( q );

    BIGNUM *oneBn = BN_new(); // Create BN = 1 
    BN_dec2bn( &oneBn , "1" );


    BN_sub( qBn , qBn , BN_value_one() ); // ( q-1)
    // Verify that r is 1 < r < (q-1)
    if (  BN_cmp( r , BN_value_one() ) != 1 ||  BN_cmp( r , qBn ) != -1 ) {
        printf("r is not between 1 and q-1.\n");
        return 0;
    }

    BN_hex2bn( &mB , digest );
    BN_mod_exp( v1 , gen , mB , q , ctx ); // calculate v1 = a^mB mod q
    BN_mod_exp( yR , y , r , q,  ctx ); // calculate y^r
    BN_mod_exp( rS , r , s, q, ctx ); // calculate x^s
    BN_mod_mul( v2 , yR , rS , q , ctx ); // y^r + x^s mod q 

    if ( BN_cmp( v1 , v2 ) == 0 ) { // Validate that v1 = v2 
        valid = 1;
    }

    BN_free(v1);
    BN_free(v2);
    BN_free(mB);
    BN_free(yR);
    BN_free(rS);
    BN_free(qBn);
    BN_free(oneBn);

    return valid;

}
