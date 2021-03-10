      /*
      1. create a context
      2. init the context
      3. init the digest: plug the digest to the context
      4. for all data: update the digest: pass data to the context
      5. finalize the context: read the digests
      6. free the context
      */

      #include <stdio.h>
      #include <openssl/evp.h>
      #include <string.h>
      #include <unistd.h>

      #define BUF_SIZE 1024

      int main(int argc,char **argv) {
              EVP_MD_CTX *md;
              unsigned char md_value[EVP_MAX_MD_SIZE];
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

              /*
              1. create a context
              2. init the context
              3. init the digest: plug the digest to the context
              4. for all data: update the digest: pass data to the context
              5. finalize the context: read the digests
              6. free the context
              */

              

  //            while((n = fread(buf,1,BUF_SIZE,fin)) > 0)





              printf("The digest is: ");
                for(i = 0; i < md_len; i++)
      			       printf("%02x", md_value[i]);
              printf("\n");

      	return 0;
      }
