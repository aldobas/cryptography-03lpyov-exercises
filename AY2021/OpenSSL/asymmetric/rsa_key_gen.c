#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main()
{
    int             ret = 0;
    RSA             *rsa_keypair = NULL;
    BIGNUM          *bne = NULL;

    int             bits = 2048;
    unsigned long   e = RSA_F4;

    // 1. generate the RSA key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }

    /*
    int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    */
    rsa_keypair = RSA_new();
    ret = RSA_generate_key_ex(rsa_keypair, bits, bne, NULL); /* callback not needed for our purposes */
    if(ret != 1){
        goto free_all;
    }


    /*
    int PEM_write_RSA_PUBKEY(FILE *fp, RSA *x); // SubjectKeyInfo: standard openssl tool format (-pubin)
    int PEM_write_RSAPublicKey(FILE *fp, RSA *x); //(-RSAPublicKey_in)
    int PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x); //PKCS#1

    */

    // 2. save public key
    BIO *bp_public = NULL;

    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa_keypair);
    // ret = PEM_write_bio_RSA_PUBKEY(bp_public, rsa_keypair);
    if(ret != 1){
        goto free_all;
    }
/*
int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                              unsigned char *kstr, int klen,
                              pem_password_cb *cb, void *u);
 int PEM_write_bio_PrivateKey_traditional(BIO *bp, EVP_PKEY *x,
                                          const EVP_CIPHER *enc,
                                          unsigned char *kstr, int klen,
                                          pem_password_cb *cb, void *u);
 int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                          unsigned char *kstr, int klen,
                          pem_password_cb *cb, void *u);
 int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cb, void *u);

*/
    // 3. save private key
    BIO *bp_private = NULL;
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa_keypair, NULL, NULL, 0, NULL, NULL);

    // TODO EXERCISE: write a password protected AES-encrypted private key
    // TODO EXERCISE: read a public or private key from file

    // 4. free
free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(rsa_keypair);
    BN_free(bne);


    return ret;
}
