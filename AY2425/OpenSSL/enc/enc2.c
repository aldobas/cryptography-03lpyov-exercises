#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0


void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{

//  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
//  int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
//  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);




    

    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[]  = "1111111111111111";



    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings(); // deprecated since version 1.1.0
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms(); // deprecated since version 1.1.0
    // void OpenSSL_add_all_ciphers(void); //ciphers only
    // void OpenSSL_add_all_digests(void); //digests only


    // pedantic mode: check NULL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    
    unsigned char plaintext[] = "This is the plaintext to encrypt."; //len=33
    unsigned char ciphertext[48];

    int update_len, final_len;
    int ciphertext_len=0;

    if(!EVP_CipherUpdate(ctx,ciphertext,&update_len,plaintext,strlen(plaintext)))
        handle_errors();

    ciphertext_len+=update_len;
    printf("update size: %d\n",ciphertext_len);

    if(!EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len))
        handle_errors();

    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext length = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");


    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data(); // deprecated since version 1.1.0
    /* Remove error strings */
    ERR_free_strings(); // deprecated since version 1.1.0

    return 0;
}

