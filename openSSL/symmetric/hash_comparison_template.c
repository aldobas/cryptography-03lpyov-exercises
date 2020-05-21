#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

#define BUF_SIZE 1024

int conv_hexstring(char *hexstring, char *digest){
  int i,byte;
  for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      sscanf(hexstring+2*i, "%2X", &byte);
      digest[i] = (char)byte;
  }
  return i;
}

int main(int argc,char **argv) {

        EVP_MD_CTX *mdctx;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        FILE *fin;
        int n,i,md_len;
        unsigned char buf[BUF_SIZE];
        unsigned char input_md[EVP_MAX_MD_SIZE];


        if(argc < 3) {
            printf("Please give the digest and the filename to compute the SHA-256 digest on\n");
            exit(1);
        }

        if((fin = fopen(argv[2],"r")) == NULL) {
                printf("Couldnt open input file, try again\n");
                exit(1);
        }

        if(strlen(argv[1]) != 2*SHA256_DIGEST_LENGTH){
          printf("Invalid hash length for the input.\n");
          exit(1);
        }

        conv_hexstring(argv[1],input_md);

        /*
        1. create a context
        2. init the context
        3. init the digest: plug the digest to the context
        4. for all data: update the digest: pass data to the context
        5. finalize the context: read the digests
        6. free the context
        7. perform the comparison
        */



       if(mdctx = EVP_MD_CTX_new() == NULL){
        fprintf(stderr,"Error in creating the context");
        exit(1);
       }

       if(1 != EVP_MD_CTX_init(mdctx)){
         fprintf(stderr,"Error in initializing the context");
         exit(1);
        }

      if(1!=EVP_DigestInit(mdctx, EVP_sha256())) {
        printf("Error when initializing the digest.\n");
        exit(1);
      }

      while((n = fread(buf,1,BUF_SIZE,fin)) > 0){
        if(1!=EVP_DigestUpdate(mdctx, buf,n)){
          printf("Error when updating the digest.\n");
          exit(1);
       }

       if(1!=EVP_DigestFinal_ex(mdctx, md_value, &md_len)) {
 				printf("Digest finalization problem\n");
 				exit(1);
         }

       EVP_MD_CTX_free(mdctx);

    printf("The digest is: ");
        for(i = 0; i < md_len; i++)
			     printf("%02x", md_value[i]);
        printf("\n");

        /*
        compare the digest in input with the one computed
        */

        if(CRYPTO_memcmp(md_value, input_md, md_len)!=0){
          printf("Digests are different\n");
        }
        else
          printf("Digest OK\n");

	return 0;
}
