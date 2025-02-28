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


    if(argc != 4){
        fprintf(stderr,"Invalid parameters. Usage: %s file_to_sign file_private_key file_public_key\n",argv[0]);
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

    
    size_t sig_len;
        if(!EVP_DigestSignFinal(sign_ctx, NULL, &sig_len))
        handle_errors();

    unsigned char signature[sig_len];

    // size_t sig_len = digest_len;
    if(!EVP_DigestSignFinal(sign_ctx, signature, &sig_len))
        handle_errors();

    EVP_MD_CTX_free(sign_ctx);

    // printf("The signature is: \n");
    //     for(int i = 0; i < sig_len; i++)
	// 		     printf("%02x", signature[i]);
    //     printf("\n");
    
    // save the signature to a file
    FILE *out = fopen("sig.bin", "w");
    if(fwrite(signature, 1,  sig_len, out) < sig_len)
        handle_errors();
    fclose(out);
    printf("Signature written to the output file.\n");

    EVP_PKEY_free(private_key);

/*********************************************************************/

    // Read the public key from the file
    
    FILE *f_pubkey;
    if((f_pubkey = fopen(argv[3],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }  
    EVP_PKEY* public_key = PEM_read_PUBKEY(f_pubkey,NULL,NULL,NULL);
    fclose(f_pubkey);

    //more controls on file opening to be really clean!
    FILE *fsig_in = fopen("sig.bin", "r");

    // Read it back
    printf("Reading the signature from file and attempting verification...\n");
    unsigned char signature_from_file [MAXBUFFER]; // we don't know in advance the size of the signature
    
    size_t sig_len_from_file;
    if ((sig_len_from_file = fread(signature_from_file, 1, MAXBUFFER, fsig_in)) != EVP_PKEY_size(public_key))
        handle_errors();
    fclose(fsig_in);
    

    // printf("The read signature is: \n");
    //     for(int i = 0; i < EVP_PKEY_size(public_key); i++)
	// 		     printf("%02x", signature_from_file[i]);
    //     printf("\n");

    EVP_MD_CTX  *verify_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestVerifyInit(verify_ctx, NULL, EVP_sha256(), NULL, public_key))
            handle_errors();
    
    // open the input file again
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }

    // these variable have been defined before
    // size_t n_read;
    // unsigned char buffer[MAXBUFFER];
    while((n_read = fread(buffer,1,MAXBUFFER,f_in)) > 0){
        if(!EVP_DigestVerifyUpdate(verify_ctx, buffer, n_read))
            handle_errors();
    }

    
    // the signature variable has been already allocated as well as the sig_len

    if(EVP_DigestVerifyFinal(verify_ctx, signature_from_file, sig_len_from_file)){
        printf("Verification successful\n");
    }
    else{
        printf("Verification failed\n");
    }

    

    EVP_MD_CTX_free(verify_ctx);



  
    EVP_PKEY_free(public_key);
     
 
    return 0;
}
