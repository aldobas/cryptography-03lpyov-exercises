// argument: filename

#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>

#define BUF_SIZE 1024

int main(int argc,char **argv) {


// useful constants can be found in the evp.h library
        unsigned char md_value[EVP_MAX_MD_SIZE]; //128, 160, 224, 256,
        int n,i,md_len;
        unsigned char buf[BUF_SIZE];
        FILE *fin;



        if(argc < 2) {
            printf("Please give a filename to compute the SHA-1 digest on\n");
            exit(1);
        }

        if((fin = fopen(argv[1],"r")) == NULL) {
                printf("Couldnt open input file, try again\n");
                exit(1);
        }


        // create a message digest context

        EVP_MD_CTX *md; //CIPHER
        //EVP_MD_CTX *EVP_MD_CTX_new(void);
        md = EVP_MD_CTX_new(); // empty context ready for computing digests

        /* init the MD context */
        //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
        // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        EVP_DigestInit_ex(md, EVP_sha1(), NULL);
        // EVP_DigestInit(md, EVP_sha1);



        /* read from file and update the context with the read content*/
        //int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);

        while( (n=fread(buf, 1, BUF_SIZE, fin)) > 0 )
            EVP_DigestUpdate(md, buf, n);


        /* finalize the context to output the digest */
        //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);

        EVP_DigestFinal_ex(md, md_value, &md_len);




        /* free the context*/
        // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
		    EVP_MD_CTX_free(md);

        printf("The digest is: ");
        for(i = 0; i < md_len; i++)
			     printf("%02x", md_value[i]);
        printf("\n");

	return 0;
}
