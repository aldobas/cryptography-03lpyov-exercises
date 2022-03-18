#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


#define KEY_LENGTH  2048
#define MAXBUFFER 1024



void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {


    if(argc != 3){
        fprintf(stderr,"Invalid parameters. Usage: %s file_to_sign file_key\n",argv[0]);
        exit(1);
    }


    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }
    FILE *f_key;
    if((f_key = fopen(argv[2],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }
    
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    // Generate key pair
    // printf("Generating a fresh RSA (%d bits) keypair...\n", KEY_LENGTH);
    // BIGNUM *bn_pub_exp = BN_new();
    // BN_set_word(bn_pub_exp,RSA_F4); 

    // RSA  *rsa_keypair; //RSA data structure
    // rsa_keypair = RSA_new();
    // RSA_generate_key_ex(rsa_keypair, KEY_LENGTH, bn_pub_exp, NULL);

    EVP_PKEY* private_key = PEM_read_PrivateKey(f_key,NULL,NULL,NULL);


    EVP_MD_CTX  *sign_ctx = EVP_MD_CTX_new();


    if(!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, private_key))
            handle_errors();
    
    size_t n_read;
    unsigned char buffer[MAXBUFFER];
    while((n_read = fread(buffer,1,MAXBUFFER,f_in)) > 0){
        if(!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();
    }

    
    unsigned char signature[EVP_PKEY_size(private_key)];
    size_t sig_len;
    size_t digest_len;
    
    if(!EVP_DigestSignFinal(sign_ctx, NULL, &digest_len))
        handle_errors();  


    if(!EVP_DigestSignFinal(sign_ctx, signature, &sig_len))
        handle_errors();

    EVP_MD_CTX_free(sign_ctx);

    
    // save the signature to a file
    FILE *out = fopen("sig.bin", "w");
    if(fwrite(signature, 1,  sig_len, out) < sig_len)
        handle_errors();
    fclose(out);
    printf("Signature written to the output file.\n");

/*********************************************************************/
/*
    // Read it back
    printf("Reading the encrypted message from file and attempting decryption...\n");
    signature = (char*)malloc(RSA_size(keypair));
    FILE *in = fopen("sig.bin", "r");
    if (fread(encrypted_data, 1, RSA_size(keypair), in) != RSA_size(keypair))
        handle_errors();
    // fclose(in);


    // Decrypt it
unsigned char decrypted_data[RSA_size(keypair)];
/*
    int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

    Error management is the same and the _encrypt function
*/

  
  
    EVP_PKEY_free(private_key);
      
    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */  
    ERR_free_strings();

    return 0;
}
