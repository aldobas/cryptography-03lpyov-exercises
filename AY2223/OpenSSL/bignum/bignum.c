#include <openssl/bn.h>

int main()
{
  // a newly instantiated BIGNUM is initialized to 0
  BIGNUM *b1=BN_new();
  BIGNUM *b2=BN_new();
  BIGNUM *b3=BN_new();
  BN_CTX *ctx=BN_CTX_new();

  // print after init
  BN_print_fp(stdout,b3);
  printf("\n");

  // roughly speaking: word functions mean -> unsigned long
  BN_set_word(b1,354);
  BN_print_fp(stdout,b1);
  printf("\n");

  BN_set_word(b2,70000000000005);
  BN_print_fp(stdout,b2);
  printf("\n");

  // b1 % b2 --> b3
  BN_mod(b3,b2,b1,ctx);

  // print in hex format
  BN_print_fp(stdout,b3);
  printf("\n");


  BN_free(b1);
  BN_free(b2);
  BN_free(b3);

  BN_CTX_free(ctx);

  return 0;
}