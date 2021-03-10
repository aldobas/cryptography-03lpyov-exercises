#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include </usr/include/stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// #define IV  "0xdeadbeefdeadbeefdeadbeefdeadbeef"
// #define KEY "0x11223344556677889900aabbccddeeff"

#define ENCRYPT 1
#define DECRYPT 0

#define BUF_SIZE 1024

int main(int argc, char **argv) {
	EVP_CIPHER_CTX *ctx;
	unsigned char ibuf[BUF_SIZE],obuf[BUF_SIZE];

	FILE *f_in, *f_out;

	int key_size,ilen,olen,tlen;


	unsigned char *key = (unsigned char *)"0123456789012345";
	unsigned char *iv  = (unsigned char *)"aabbccddeeffaabb";

	int i;

	printf("key is: ");
	for(i = 0; i < 16; i++)
			printf("%02x", key[i]);
	printf("\n");

	printf("IV is: ");
	for(i = 0; i < 16; i++)
			printf("%02x", iv[i]);
	printf("\n");

	key_size=EVP_CIPHER_key_length(EVP_aes_128_cbc());
	printf("key size = %d\n",key_size);



/**************************************************************/

unsigned char *long_message = (unsigned char *)"this is a very long message I will split in parts";
printf("len(long_message) = %d\n",strlen(long_message));

ctx=EVP_CIPHER_CTX_new();
EVP_CIPHER_CTX_init(ctx);
EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, ENCRYPT);

int tot = 0;
EVP_CipherUpdate(ctx,obuf,&olen,long_message,strlen(long_message));
printf("olen = %d\n",olen);
tot += olen;

EVP_CipherFinal_ex(ctx,obuf+tot,&tlen);
tot += tlen;
printf("tot = %d\n",tot);
printf("tlen = %d\n",tlen);

printf("output is: ");
for(i = 0; i < tot; i++)
		printf("%02x", obuf[i]);
printf("\n");


EVP_CIPHER_CTX_free(ctx);

/**************************************************************/

int split_index = 18;

ctx=EVP_CIPHER_CTX_new();
EVP_CIPHER_CTX_init(ctx);
EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, ENCRYPT);

tot = 0;
EVP_CipherUpdate(ctx,obuf,&olen,long_message,split_index);
printf("olen = %d\n",olen);
tot += olen;

EVP_CipherUpdate(ctx,obuf+tot,&olen,long_message+split_index,strlen(long_message)-split_index);
printf("olen = %d\n",olen);
tot += olen;

EVP_CipherFinal_ex(ctx,obuf+tot,&tlen);
tot += tlen;
printf("tot = %d\n",tot);
printf("tlen = %d\n",tlen);

printf("output is: ");
for(i = 0; i < tot; i++)
		printf("%02x", obuf[i]);
printf("\n");


EVP_CIPHER_CTX_free(ctx);


/**************************************************************/

int split_index2 = 4;

ctx=EVP_CIPHER_CTX_new();
EVP_CIPHER_CTX_init(ctx);
EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, ENCRYPT);

tot = 0;
EVP_CipherUpdate(ctx,obuf,&olen,long_message,split_index);
printf("olen = %d\n",olen);
tot += olen;

EVP_CipherUpdate(ctx,obuf,&olen,long_message+split_index,split_index2);
printf("olen = %d\n",olen);
tot += olen;

EVP_CipherUpdate(ctx,obuf+tot,&olen,long_message+split_index+split_index2,strlen(long_message)-split_index-split_index2);
printf("olen = %d\n",olen);
tot += olen;

EVP_CipherFinal_ex(ctx,obuf+tot,&tlen);
tot += tlen;
printf("tot = %d\n",tot);
printf("tlen = %d\n",tlen);

printf("output is: ");
for(i = 0; i < tot; i++)
		printf("%02x", obuf[i]);
printf("\n");


EVP_CIPHER_CTX_free(ctx);


	return 0;
}
