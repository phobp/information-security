/*----------------------------------------------------------------------------
Demonstration of BIGBUM in openssl
Written By: 
     1- Dr. Mohamed Aboutabl
----------------------------------------------------------------------------*/
#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------

int main()
{
    
    BN_CTX *ctx; /* used internally by the bignum lib */
    int    bnSize;

    OPENSSL_config(NULL);

    ctx      = BN_CTX_new();

    // Generate a 512-bit safe prime number whose generator (primitive root) is 2
    const BIGNUM    *pp , *qq , *gg ;
    BIGNUM          *prmtvRoot, *prime;
    DH              *dhObject;

    prmtvRoot = BN_new();
    prime     = BN_new();
    dhObject  = DH_new() ;

    if( 1 != DH_generate_parameters_ex( dhObject, 512 , 2 , NULL) )
        handleErrors("Amal: DH_generate");

    DH_get0_pqg( dhObject , &pp, &qq , &gg ) ;

    BN_copy( prmtvRoot , gg ) ;   // i.e. 2 as a BIGNUM
    BN_copy( prime     , pp ) ;   // the prime number
    DH_free( dhObject ) ;

    printf("\nThe \"prime\" number \n\tin Hex: = ") ;
    if( 1 != BN_print_fp( stdout , prime ) )
        handleErrors("BN_print_fp");
    printf("\n\tin Dec: = %s \n" ,  BN_bn2dec(prime) );
    // Test for primality
    switch( BN_is_prime_ex( prime , BN_prime_checks , ctx, NULL ) )
    {
        case  0: printf("\nwhich is NOT prime\n") ; break ;
        case  1: printf("\nwhich is most probably prime\n") ; break ;
        case -1: handleErrors("BN_is_prime_ex()") ;
    }
   
    printf("\nThe primitive root is: Hex ") ;
    if( 1 != BN_print_fp( stdout , prmtvRoot ) )
        handleErrors("BN_print_fp") ;
    printf("\n") ;

    BIGNUM *x , *y ;
    x = BN_new() ;
    y = BN_new() ;
    if ( 0 == BN_set_word( x , 19 ) )   // x = 19
        handleErrors("set_word" );    

        BN_mod_exp( y , prmtvRoot , x , prime , ctx ) ;

    printf("\nMy private x (%d bytes) is: \tHex " , BN_num_bytes(x) )  ; 
        BN_print_fp( stdout , x ) ;  
        printf(" = \tDec %s\n" , BN_bn2dec(x) ) ;

    printf("\nMy public (%s ^ %s) mod %s \n\t= Hex " , BN_bn2dec(prmtvRoot) , BN_bn2dec(x ) , BN_bn2dec(prime))  ; 
        BN_print_fp( stdout , y)  ;  
        printf("\n\t= Dec %s\n" , BN_bn2dec(y) ) ;

    // Demo of Modular Multiplicative Inverse
    BIGNUM  *k , *kInv , *product;
    k = BN_new() ;
    kInv = BN_new() ;
    
    if ( 0 == BN_set_word( k , 23 ) )   // k = 23
        handleErrors("set_word" );    
    printf("\nk (%d bytes) = %s\n", BN_num_bytes(k) , BN_bn2dec(k) );

    kInv = BN_mod_inverse( NULL , k , prime , ctx ) ;
    printf("\nInv(%s) mod %s \n\t= %s\n", BN_bn2dec(k) , BN_bn2dec(prime), BN_bn2dec(kInv) );

    // Test if k *  kInv is indeed equal to 1
    product = BN_new() ;
    BN_mod_mul( product , k , kInv , prime , ctx ) ;
    printf("\nTheir procduct is:\t") ; BN_print_fp( stdout , product) ;  printf("\n") ;
    BN_clear_free( product );
    printf("\n");
 
    // End of Demo
    BN_clear_free( x );
    BN_clear_free( y );
    BN_clear_free( k );
    BN_clear_free( kInv );
    BN_clear_free( prmtvRoot );
    BN_clear_free( prime );
    BN_CTX_free(ctx); 

}
