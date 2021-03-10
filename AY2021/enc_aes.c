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



//https://www.openssl.org/docs/man1.1.0/man3/EVP_CipherInit_ex.html

/*
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
*/
	ctx=EVP_CIPHER_CTX_new();

/*
void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
*/

	EVP_CIPHER_CTX_init(ctx);


/*
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
*/
	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, ENCRYPT);

// 	if(1 !=  EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, ENCRYPT);) {
// 		printf("Couldnt initialize cipher\n");
//         exit(1);
// 	}
//


unsigned char *message = (unsigned char *)"this is amessage";
printf("message is: ");
for(i = 0; i < strlen(message); i++)
		printf("%02x", message[i]);
printf("\n");
/*
int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, const unsigned char *in, int inl);
 int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
         int *outl);
*/

int tot = 0;
EVP_CipherUpdate(ctx,obuf,&olen,message,strlen(message));
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

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////


ctx=EVP_CIPHER_CTX_new();
EVP_CIPHER_CTX_init(ctx);
EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, DECRYPT);

unsigned char decrypted[BUF_SIZE];

int tot_dec = 0;
EVP_CipherUpdate(ctx,decrypted,&olen,obuf,tot);
printf("olen = %d\n",olen);
tot_dec += olen;
EVP_CipherFinal_ex(ctx,decrypted+olen,&tlen);
tot_dec += tlen;
printf("tot = %d\n",tot_dec);

printf("decrypted is: ");
for(i = 0; i < tot_dec; i++)
		printf("%02x", decrypted[i]);
printf("\n");


EVP_CIPHER_CTX_free(ctx);

return 0;
}
