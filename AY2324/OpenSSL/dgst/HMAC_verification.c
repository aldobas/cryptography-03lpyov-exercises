#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char **argv){
       
       unsigned char key[] = "deadbeefdeadbeef";
       //unsigned char hmac[] = "bf768f20555d7a1f20e77ad34351dcc614fc63f7";
      
        if(argc != 3){
            fprintf(stderr,"Invalid parameters. Usage: %s filename HMAC\n",argv[0]);
            exit(1);
        }


        FILE *f_in;
        if((f_in = fopen(argv[1],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file, try again\n");
                exit(1);
        }


        /* Load the human readable error strings for libcrypto */
        ERR_load_crypto_strings();
        /* Load all digest and cipher algorithms */
        OpenSSL_add_all_algorithms();

       //pedantic mode? Check if md == NULL
		HMAC_CTX  *hmac_ctx = HMAC_CTX_new();

        if(!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha1(), NULL))
            handle_errors();

        int n;
        unsigned char buffer[MAXBUF];
        while((n = fread(buffer,1,MAXBUF,f_in)) > 0){
        // Returns 1 for success and 0 for failure.
            if(!HMAC_Update(hmac_ctx, buffer, n))
                handle_errors();
        }

        unsigned char hmac_value[HMAC_size(hmac_ctx)];
        int hmac_len;


        if(!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
            handle_errors();

		HMAC_CTX_free(hmac_ctx);

        printf("The computed HMAC is: ");
        for(int i = 0; i < hmac_len; i++)
			     printf("%02x", hmac_value[i]);
        printf("\n");
        printf("The received HMAC is: %s\n",argv[2]);


        // VERIFICATION PART
        unsigned char hmac_binary[strlen(argv[2])/2];
        for(int i = 0; i < strlen(argv[2])/2;i++){
            sscanf(&argv[2][2*i],"%2hhx", &hmac_binary[i]);
        }

        // if( CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) == 0 )
        if( (hmac_len == (strlen(argv[2])/2)) && (CRYPTO_memcmp(hmac_binary, hmac_value, hmac_len) == 0))

             printf("Verification successful\n");
        else
            printf("Verification failed\n");



        // completely free all the cipher data
        CRYPTO_cleanup_all_ex_data();
        /* Remove error strings */
        ERR_free_strings();


	return 0;

}