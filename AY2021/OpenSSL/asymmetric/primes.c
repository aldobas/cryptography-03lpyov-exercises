#include <openssl/bn.h>
#include <openssl/rand.h>
// #include <openssl/bio.h>
#include <openssl/err.h>
// #include <openssl/bioerr.h>

int main(){

/*
int BN_generate_prime_ex(BIGNUM *ret,int bits,int safe, const BIGNUM *add,
     const BIGNUM *rem, BN_GENCB *cb);
*/
  BIGNUM *prime1=BN_new();
  BIGNUM *prime2=BN_new();

  /* init the random engine: YOU MUST DOI IT!!!! */
  int rc = RAND_load_file("/dev/random", 32);
  if(rc != 32) {
    ERR_print_errors_fp(stdout);
    exit(1);
  }

  //16 bit prime
  // int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add,
  //      const BIGNUM *rem, BN_GENCB *cb);
  // safe == 1 --> (p-1)/2 is also prime
  // p % add == rem
  if (!BN_generate_prime_ex(prime1, 16, 0, NULL, NULL, NULL)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

  BN_print_fp(stdout,prime1);
  printf("\n");

  /*
  When the source of the prime is not random or not trusted, the number of
  checks needs to be much higher to reach the same level of assurance:
  It should equal half of the targeted security level in bits (rounded up to
  the next integer if necessary). For instance, to reach the 128 bit security
  level, nchecks should be set to 64.
  */
  // int BN_is_prime_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb);
  if(BN_is_prime_ex(prime1,8,NULL,NULL)){
    printf("Yes, it's a prime\n");
  }
  else{
    printf("No, it isn't a prime\n");
  }

  BN_set_word(prime2,128);
  if(BN_is_prime_ex(prime2,8,NULL,NULL)){
    printf("Yes, it's a prime\n");
  }
  else{
    printf("No, it isn't a prime\n");
  }


  /*
  int BN_num_bytes(const BIGNUM *a);
  int BN_num_bits(const BIGNUM *a);
  int BN_num_bits_word(BN_ULONG w);
  */

  printf("Num bytes of prime1 is %d\n",BN_num_bytes(prime1));
  printf("Num bytes of prime2 is %d\n",BN_num_bits(prime2));


 /*
 int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);

 BN_rand() generates a cryptographically strong pseudo-random number of bits
 bits in length and stores it in rnd. If top is -1, the most significant bit of
 the random number can be zero. If top is 0, it is set to 1, and if top is 1,
 the two most significant bits of the number will be set to 1, so that the
 product of two such random numbers will always have 2*bits length. If bottom
 is true, the number will be odd.
 top
  -1 --> 0 ....
  0 --> 1 ....
  1 --> 11 ...

  bottom
  1 --> ... 1
 */
 BIGNUM *rand_num = BN_new();
 BN_rand(rand_num,32,0,1);

 BN_print_fp(stdout,rand_num);
 printf("\n");

 /*
 BN_ULONG BN_get_word(BIGNUM *a);
 */

 printf("Not so big num value: %u\n",BN_get_word(rand_num));
 if(BN_is_prime_ex(rand_num,16,NULL,NULL)){
   printf("Yes, it's a prime\n");
 }
 else{
   printf("No, it isn't a prime\n");
 }

}
