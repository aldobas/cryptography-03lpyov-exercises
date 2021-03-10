#include <stdio.h>
#include <openssl/evp.h>
#include </usr/include/stdlib.h>
#include <string.h>


#define ENCRYPT 1
#define DECRYPT 0

#define BUF_SIZE 1024

int main(int argc, char **argv) {

	unsigned char ibuf[BUF_SIZE],obuf[BUF_SIZE];

	int key_size,ilen,olen,tlen;

	// input: string
	//AES-128-CBC
	//output: encrypted string
	//

	// key
	unsigned char *key = (unsigned char *)"0123456789012345";
	// -K 012345 --> 01 0000 0001 0000 0010 ...
	// iv
	unsigned char *iv  = (unsigned char *)"aaaaaaaaaaaaaaaa";
	// 1010 1010 1010...
	int i;
	printf("key is: ");
	for(i = 0; i < 16; i++)
			printf("%02x", key[i]);
	printf("\n");

	printf("IV is: ");
	for(i = 0; i < 16; i++)
			printf("%02x", iv[i]);
	printf("\n");


/* algorithm EVP_aes_128_cbc()  openssl enc*/
	key_size = EVP_CIPHER_key_length(EVP_aes_128_cbc());
	printf("key size = %d\n",key_size);



/**
 start Encryption
**/

//https://www.openssl.org/docs/man1.1.0/man3/EVP_CipherInit_ex.html
// creating the object --> context
EVP_CIPHER_CTX *ctx;

/*
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
*/
ctx = EVP_CIPHER_CTX_new();

/*
void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
*/
EVP_CIPHER_CTX_init(ctx);
// an object ready to do something with symmetric crypto

/*
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
*/

// plug-in: AES 128 EVP_aes_128_cbc
// use this key
// use this IV
// use this ENGINE
EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, ENCRYPT);



/* message: 16 bytes = 1 block */
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
// char obuf[2048];
EVP_CipherUpdate(ctx, obuf, &olen, message, strlen(message));
printf("olen = %d\n",olen);
tot += olen;
// obuf [ 1111111111111111 1010101010101 ]
// tot == 16
EVP_CipherFinal_ex(ctx, obuf+tot, &olen);
tot += olen;

printf("tot = %d\n",tot);
printf("olen = %d\n",tlen);

printf("output is: ");
for(i = 0; i < tot; i++)
		printf("%02x", obuf[i]);
printf("\n");

/* free the context */
EVP_CIPHER_CTX_free(ctx);

/////////////////////////////////////////////////////////////////
// decrypt what has just been encrypted
/////////////////////////////////////////////////////////////////

ctx = EVP_CIPHER_CTX_new();
EVP_CIPHER_CTX_init(ctx);
EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, DECRYPT);

int tot_dec = 0;
unsigned char decrypted[BUF_SIZE];

EVP_CipherUpdate(ctx, decrypted, &olen, obuf, tot);
printf("olen = %d\n",olen);
tot_dec += olen;


EVP_CipherFinal_ex(ctx, decrypted+tot_dec, &tlen);
tot_dec += tlen;

printf("tot = %d\n",tot_dec);
printf("olen = %d\n",tlen);

printf("decrypted is: ");
for(i = 0; i < tot_dec; i++)
		printf("%02x", decrypted[i]);
printf("\n");

/* free the context */
EVP_CIPHER_CTX_free(ctx);




return 0;
}
