#include <openssl/bn.h>

int main()
{

  BIGNUM *b1 = BN_new();
  BIGNUM *b2 = BN_new();
  BIGNUM *b3 = BN_new();

  //

  // after initialization value is 0
  // print
  BN_print_fp(stdout,b1); // hex
  puts("");

  // set_word to assign values --> unsigned long
  BN_set_word(b1,354);
  BN_set_word(b2,33);

  BN_print_fp(stdout,b1); // hex
  puts("");
  BN_print_fp(stdout,b2); // hex
  puts("");


  //simple mod operation:
  BN_CTX *ctx = BN_CTX_new();

  BN_mod(b3,b1,b2,ctx);

  //BN_bn2dec to print the decimal value

  printf("mod = %s\n",BN_bn2dec(b3));

  // after usage: free all the memory

  BN_free(b1);
  BN_free(b2);
  BN_free(b3);

  BN_CTX_free(ctx);

  return 0;
}
