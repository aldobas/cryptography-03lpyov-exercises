#include <stdio.h>
#include </usr/include/stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


int main(int argc, char **argv) {
	unsigned char key[EVP_MAX_KEY_LENGTH];
	FILE *key_file;
	int key_size;

	if(argc < 3) {
			fprintf(stderr, "Usage: %s algorithm outfile\n",argv[0]);
			exit(-1);
	}


  if((key_file = fopen(argv[2],"w")) == NULL) {
          fprintf(stderr, "Problems with the output file\n");
          exit(-2);
  }


  const EVP_CIPHER *algo;

  //const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
  if ((algo = EVP_get_cipherbyname(argv[1])) == NULL){
    fprintf(stderr, "Unknown algorithm\n");
    exit(-3);
}

  key_size=EVP_CIPHER_key_length(algo);

	int rc = RAND_load_file("/dev/random", 32);
	if(rc != 32) {
		fprintf(stderr, "Couldnt initialize the PRNG\n");
    exit(-4);
	}


  RAND_bytes(key,key_size);

  if(fwrite(key , 1 , key_size , key_file) != key_size){
    fprintf(stderr, "Error writing on file\n");
    exit(-5);
  }

	return 0;
}
