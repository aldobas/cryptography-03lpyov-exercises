#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include </usr/include/stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define IV "0xdeadbeefdeadbeef"

#define ENCRYPT 1
#define DECRYPT 0

#define BUF_SIZE 1024

int main(int argc, char **argv) {
	EVP_CIPHER_CTX *ctx;
	unsigned char key[BUF_SIZE],iv[BUF_SIZE],ibuf[BUF_SIZE],obuf[BUF_SIZE];
	int rfd, wfd,keyfd;
	int key_size,ilen,olen,tlen;
	int fd;

	if(argc < 3) {
			printf("Usage: %s infile outfile\n",argv[0]);
			exit(128);
	}


	if((rfd = open(argv[1],O_RDONLY) ) == -1) {
		printf("Couldnt open input file\n");
		exit(128);
	}
	if((wfd = creat(argv[2],0644) ) == -1) {
		printf("Couldn't open output file for writing\n");
		exit(128);
	}

	int rc = RAND_load_file("/dev/random", 32);
	if(rc != 32) {
		printf("Couldnt initialize PRNG\n");
    exit(1);
	}
	key_size=EVP_CIPHER_key_length(EVP_aes_256_cbc());
	RAND_bytes(key,key_size);

	keyfd = creat(".key",0644);
	write(keyfd,key,key_size);
	close(keyfd);

/* EXERCISE: init IV with random values and write it in a file */
	memcpy(iv,IV,sizeof(IV));

	ctx=EVP_CIPHER_CTX_new();
 	EVP_CIPHER_CTX_init(ctx);
	if(1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, ENCRYPT) ) {
		printf("Couldnt initialize cipher\n");
        exit(1);
	}

	while((ilen = read(rfd,ibuf,BUF_SIZE) ) > 0) {
		if(1 == EVP_CipherUpdate(ctx,obuf,&olen,ibuf,ilen)){
			write(wfd,obuf,olen);
		}
		else {
			printf("Encryption error\n");
			return 1;
		}
	}

	if(1 != EVP_CipherFinal_ex(ctx,obuf+olen,&tlen)) {
		printf("Trouble with padding the last block\n");
		return 1;
	}

	write(wfd,obuf+olen,tlen);

	EVP_CIPHER_CTX_free(ctx);
	//EVP_CIPHER_CTX_reset(ctx);
	close(rfd);
	close(wfd);

	int i;
	printf("key is: ");
	for(i = 0; i < key_size; i++)
			printf("%02x", key[i]);
	printf("\n");

	printf("AES 256 CBC encryption complete\n");
	printf("Secret key is saved to file .key\n");

	return 0;
}
