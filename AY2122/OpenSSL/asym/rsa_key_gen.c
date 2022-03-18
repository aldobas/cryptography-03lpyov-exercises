#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}



int main()
{

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();


    // int ret = 0;
    RSA *rsa_keypair = NULL;
    BIGNUM *bne = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    // 1. generate the RSA key
    bne = BN_new();
    if(!BN_set_word(bne,e))
        handle_errors();

    /*
    int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    */
    rsa_keypair = RSA_new();
    if(!RSA_generate_key_ex(rsa_keypair, bits, bne, NULL)) /* callback not needed for our purposes */
        handle_errors();


    /*
    int PEM_write_RSA_PUBKEY(FILE *fp, RSA *x); // SubjectKeyInfo: standard openssl tool format (-pubin)
    int PEM_write_RSAPublicKey(FILE *fp, RSA *x); //(-RSAPublicKey_in)
    int PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x); //PKCS#1
    */

    // 2. save public key
    FILE *rsa_public_file = NULL;
    if((rsa_public_file = fopen("public.pem","w")) == NULL) {
            fprintf(stderr,"Couldn't create the private key file.\n");
            abort();
    }
    if(!PEM_write_RSA_PUBKEY(rsa_public_file, rsa_keypair))
        handle_errors();
    fclose(rsa_public_file);
/*
 int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                          unsigned char *kstr, int klen,
                          pem_password_cb *cb, void *u);
 int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cb, void *u);

*/
    // 3. save private key
    FILE *rsa_private_file = NULL;
        if((rsa_private_file = fopen("private.pem","w")) == NULL) {
                fprintf(stderr,"Couldn't create the private key file.\n");
                abort();
        }
    if(!PEM_write_RSAPrivateKey(rsa_private_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();
    fclose(rsa_public_file);


    // TODO EXERCISE: write a password protected AES-encrypted private key
    // TODO EXERCISE: read a public or private key from file

    // 4. free
    RSA_free(rsa_keypair);
    BN_free(bne);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();


    return 0;
}
