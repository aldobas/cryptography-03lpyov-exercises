#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAX_ENC_LEN 1000000
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{

//  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
//  int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
//  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);


    


    if(argc != 4){
        fprintf(stderr,"Invalid parameters. Usage: %s filename key iv\n",argv[0]);
        exit(1);
    }


    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
            fprintf(stderr,"Couldn't open the input file, try again\n");
            abort();
    }

    if(strlen(argv[2])!=32){
        fprintf(stderr,"Wrong key length\n");
        abort();
    }   
    if(strlen(argv[3])!=32){
        fprintf(stderr,"Wrong IV length\n");
        abort();
    }
        

        

    unsigned char key[strlen(argv[2])/2];
    for(int i = 0; i < strlen(argv[2])/2;i++){
        sscanf(&argv[2][2*i],"%2hhx", &key[i]);
    }

    unsigned char iv[strlen(argv[3])/2];
    for(int i = 0; i < strlen(argv[3])/2;i++){
        sscanf(&argv[3][2*i],"%2hhx", &iv[i]);
    }


    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings(); // deprecated since version 1.1.0
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms(); // deprecated since version 1.1.0

    // pedantic mode: check NULL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    
    
    unsigned char ciphertext[MAX_ENC_LEN];

    int update_len, final_len;
    int ciphertext_len=0;
    int n_read;
    unsigned char buffer[MAX_BUFFER];


    while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
        if(ciphertext_len > MAX_ENC_LEN - n_read - EVP_CIPHER_CTX_block_size(ctx)){ //use EVP_CIPHER_get_block_size with OpenSSL 3.0+ instead
            fprintf(stderr,"The file to cipher is larger than I can manage\n");
            abort();
        }
    
        if(!EVP_CipherUpdate(ctx,ciphertext+ciphertext_len,&update_len,buffer,n_read))
            handle_errors();
        ciphertext_len+=update_len;
    }

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

