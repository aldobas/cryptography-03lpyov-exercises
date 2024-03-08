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



    EVP_PKEY *rsa_keypair = NULL;
    int bits = 2048;

    /*
    EVP_PKEY *EVP_RSA_gen(unsigned int bits);
    */
    ;
    if((rsa_keypair = EVP_RSA_gen(bits)) == NULL ) 
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
    if(!PEM_write_PUBKEY(rsa_public_file, rsa_keypair))
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
    // 3. save private key (without encrypting it on disk)
    FILE *rsa_private_file = NULL;
        if((rsa_private_file = fopen("private.pem","w")) == NULL) {
                fprintf(stderr,"Couldn't create the private key file.\n");
                abort();
        }
    if(!PEM_write_PrivateKey(rsa_private_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();
    fclose(rsa_public_file);


    // TODO EXERCISE: write a password protected AES-encrypted private key
    // TODO EXERCISE: read a public or private key from file

    // 4. free
    EVP_PKEY_free(rsa_keypair);
    

    return 0;
}
