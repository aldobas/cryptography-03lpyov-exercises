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


    /*
     int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
     */
     bne = BN_new();
     BN_set_word(bne,e);
     rsa_keypair = RSA_new();
     ret = RSA_generate_key_ex(rsa_keypair,bits, bne, NULL);
     /* 1 on success 0 on error */
     if(ret != 1){
       /* */
     }

     // pub and pri RSA parameters both in rsa_keypair
     BIO *bio_public;
     bio_public = BIO_new_file("public.pem","w+");
     /*
     int PEM_write_RSA_PUBKEY(FILE *fp, RSA *x); // SubjectKeyInfo: standard openssl tool format (-pubin)
     int PEM_write_RSAPublicKey(FILE *fp, RSA *x); //(-RSAPublicKey_in)
     int PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x); //PKCS#1
 BIO
     */
     // PEM_write_bio_RSAPublicKey(bio_public,rsa_keypair);
     PEM_write_bio_RSA_PUBKEY(bio_public,rsa_keypair);
     if(ret != 1){
       /* */
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
   BIO *bio_private;
   bio_private = BIO_new_file("private.pem","w+");
   PEM_write_bio_RSAPrivateKey(bio_private, rsa_keypair, NULL, NULL, 0, NULL, NULL );


   BIO_free_all(bio_public);
   BIO_free_all(bio_private);
   RSA_free(rsa_keypair);
   BN_free(bne);

   return 0;

}
