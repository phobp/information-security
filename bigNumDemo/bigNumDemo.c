/*----------------------------------------------------------------------------
Demonstration of BIGBUM in openssl
Written By: 
     1- Dr. Mohamed Said Aboutabl
----------------------------------------------------------------------------*/

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
int main()
{
    BIGNUM *someBN;
    BN_CTX *ctx; /* used internally by the bignum lib */
    int    bnSize;

    ctx    = BN_CTX_new();

    // Decimal to BIGNUM and back
    if( 0 == BN_dec2bn( &someBN, "20988936657440586486151264256610222593863921" ) )   // some large someBN
        handleErrors("dec2bn") ;

    bnSize = BN_num_bytes(someBN) ; // How many bytes its value occupies in memory
    printf("This value of someBN is %s (%d bytes in memory).", BN_bn2dec(someBN) , bnSize  );

    switch( BN_is_prime_ex( someBN , BN_prime_checks , ctx , NULL) )
    {
        case  0: printf(" It is not prime\n"); break ;
        case  1: printf(" It is most probably prime\n"); break ;
        case -1: handleErrors("BN_is_prime_ex()") ;
    }

    // Getting the binary value of a BIGNUM in Big-Endian
    bnSize = BN_num_bytes(someBN) ; // How many bytes its value occupies in memory
    unsigned char *bnDump = malloc( bnSize) ;
    if( bnDump == NULL )
        handleErrors("malloc");
    BN_bn2bin( someBN , bnDump ) ;   // get the binary value in Big Endian
    printf("It's stored in memory as (Big-Endian):\n");
    BIO_dump_fp( stdout , bnDump , bnSize ) ;

    // Setting a BIGNUM to some unsigned (maybe Long) Integer
    if ( 0 == BN_set_word( someBN , 5000000000L ) )   // someBN = some value
        handleErrors("set_word" );    
    printf("\nsomeBN (%d bytes) =%s\n", BN_num_bytes(someBN) , BN_bn2dec(someBN) );

    // Demo of modular exponentiation
    if ( 0 == BN_set_word( someBN , 19L ) )   // someBN = 19
        handleErrors("set_word" );    
    printf("\nsomeBN (%d bytes) = %s\n", BN_num_bytes(someBN) , BN_bn2dec(someBN) );

    BIGNUM *gen ;
    gen    = BN_new();

    if ( 0 == BN_set_word( gen , 10 ) )     // primitive root = 10
        handleErrors("set_word" );    
    printf("Primitive root, a.k.a. generator, (%d bytes) = %s\n",
           BN_num_bytes(gen) , BN_bn2dec(gen) );

    BIGNUM *a, *b, *c, *d ;
    a      = BN_new();
    b      = BN_new();
    c      = BN_new();
    for( int i=1; i<30 ; i++)
    {
        if( 0 == BN_set_word( b , i ) )                     // b = i
            handleErrors("set_word" );
        if( 0  == BN_mod_exp( c , gen , b , someBN , ctx ) )   // c = (gen^b) mod someBN
            handleErrors("Modular Exponentiation"); 

        printf("( %s ^ %3d) mod %s = %5s\n",  BN_bn2dec(gen) , i , 
                BN_bn2dec(someBN) , BN_bn2dec(c) );
    }

    // Demo of BIGNUM  mult an Integer, and of Duplicating a BIGNUM
    if( 0 == BN_set_word(a, 27L) )
        handleErrors("set_word") ;

    if( 0 == BN_dec2bn( &b, "12345678901234567890" ) )   // b = some large value
        handleErrors("dec2bn") ;

    if( 0 == BN_mod_mul( c, a, b, someBN , ctx) ) // c = (a * b) mod someBN
        handleErrors("set_word") ;

    if ( NULL == (d = BN_dup(c) ) )
        handleErrors("BN_dup");

    printf("(%s * %s) mod %s = %s\n", BN_bn2dec(a) , BN_bn2dec(b) , 
                                     BN_bn2dec(someBN) , BN_bn2dec(d) );

    // Must free all BIGNUM objects
    BN_free( a );       // frees up memory, but leaves value of a behind as garbage (not secure)
    BN_clear_free( b );
    BN_clear_free( c );
    BN_clear_free( d );
    BN_clear_free( gen );
    BN_clear_free( someBN );
    BN_CTX_free(ctx); 

}
