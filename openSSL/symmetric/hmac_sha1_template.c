#include <stdio.h>
#include <openssl/hmac.h>
#include <string.h>
#include <openssl/err.h>

#define KEY "deadbeefdeadbeef"

#define BUF_SIZE 1024

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}



int main(int argc,char **argv) {
        HMAC_CTX *hmac_ctx;

        int n,i,len;
        unsigned char buf[BUF_SIZE],hmac_value[EVP_MAX_MD_SIZE];

        FILE *fin;

        if(argc < 2) {
                printf("Please give a filename to compute the HMAC on\n");
                return 1;
        }

        if((fin = fopen(argv[1],"r")) == NULL) {
                printf("Couldnt open input file, try again\n");
                exit(1);
        }
        
        /*
        1. create a context
        2. init the MAC context
        3. init the MAC: plug the digest and the key to the context
        4. for all data: update the MAC: pass data to the context
        5. finalize the context: read the MAC
        6. free the context
        */




//         while((n = fread(buf,1,BUF_SIZE,fin)) > 0)



        printf("MAC is: ");
        for(i = 0; i < len; i++)
          printf("%02x", hmac_value[i]);
        printf("\n");

return 0;


}
