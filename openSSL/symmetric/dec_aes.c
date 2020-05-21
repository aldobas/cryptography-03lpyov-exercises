#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/err.h>

#define IV "0xdeadbeefdeadbeef"

#define BUF_SIZE 2048


#define ENCRYPT 1
#define DECRYPT 0


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
        EVP_CIPHER_CTX *ctx;
        unsigned char key[BUF_SIZE],iv[BUF_SIZE],ibuf[BUF_SIZE],obuf[BUF_SIZE+16];
        int rfd, wfd,keyfd,ilen,olen,tlen,key_size;
        int l = 0;


        if(argc < 3) {
                printf("Usage: %s infile outfile\n",argv[0]);
                exit(128);
        }

        /*EXERCISE: read the IV from a file */
        memcpy(iv,IV,sizeof(IV));


        key_size=EVP_CIPHER_key_length(EVP_aes_256_cbc());
        keyfd = open(".key",O_RDONLY);
        read(keyfd,key,key_size);
        close(keyfd);

        // int i;
        // printf("key is: ");
        // for(i = 0; i < key_size; i++)
        //     printf("%02x", key[i]);
        // printf("\n");

        ctx=EVP_CIPHER_CTX_new();

        EVP_CIPHER_CTX_init(ctx);
/* last parameter 1 for encrypt, 0 for decrypt */
        if(1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(),NULL,key, iv,DECRYPT) ) {
          printf("Couldnt initialize cipher\n");
          return 1;
        }

        if((rfd = open(argv[1],O_RDONLY) ) == -1) {
                printf("Couldnt open input file\n");
                exit(128);
        }
        if((wfd = creat(argv[2],0644) ) == -1) {
                printf("Couldn't open output file for writing\n");
                exit(128);
        }

        while((ilen = read(rfd,ibuf,BUF_SIZE) ) > 0) {
                printf("ilen=%d\n",ilen);

                int i;

                if(1 == EVP_CipherUpdate(ctx,obuf,&olen,ibuf,ilen)){
                        write(wfd,obuf,olen);
                        printf("olenOK=%d\n",olen);
                }
                else {
                        printf("olen=%d\n",olen);
                        printf("Decryption error\n");
                        handleErrors();
                        return 1;
                }

        }
        if(!EVP_CipherFinal_ex(ctx,obuf+olen,&tlen)) {
                printf("Trouble with unpadding the last block\n");
                return 1;
        }
        write(wfd,obuf+olen,tlen);

        EVP_CIPHER_CTX_free(ctx);
        close(rfd);
        close(wfd);

        printf("AES 256 CBC decryption complete\n");

        return 0;
}
