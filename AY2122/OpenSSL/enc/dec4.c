#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{

//int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
//int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

//  int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv);
//  int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

//  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
//  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);



    if(argc != 5){
        fprintf(stderr,"Invalid parameters. Usage: %s file_in key iv file_out\n",argv[0]);
        exit(1);
    }


    FILE *f_in;
    if((f_in = fopen(argv[1],"r")) == NULL) {
            fprintf(stderr,"Couldn't open the input file, try again\n");
            abort();
    }
 
    if(strlen(argv[2])!=32){
        fprintf(stderr,"Wrong key lenght\n");
        abort();
    }   
    if(strlen(argv[3])!=32){
        fprintf(stderr,"Wrong IV lenght\n");
        abort();
    }
    
    FILE *f_out;
    if((f_out = fopen(argv[4],"wb")) == NULL) {
            fprintf(stderr,"Couldn't open the output file, try again\n");
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
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    // pedantic mode: check NULL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, DECRYPT))
        handle_errors();

    

    int lenght;
    unsigned char plaintext[MAX_BUFFER+16];

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){
        if(!EVP_CipherUpdate(ctx,plaintext,&lenght,buffer,n_read))
            handle_errors();

        if(fwrite(plaintext, 1, lenght,f_out) < lenght){
            fprintf(stderr,"Error writing the output file\n");
            abort();
        }
    }
            
    if(!EVP_CipherFinal_ex(ctx,plaintext,&lenght))
        handle_errors();

    // for(int i = 0; i < lenght; i++)
    //     printf("%02x", ciphertext[i]);
    // printf("\n");



    if(fwrite(plaintext,1, lenght, f_out) < lenght){
        fprintf(stderr,"Error writing in the output file\n");
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    fclose(f_in);
    fclose(f_out);

    printf("File decrypted!\n");


    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}

