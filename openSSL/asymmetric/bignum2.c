#include <stdio.h>
#include <openssl/bn.h>

int main ()
{
  char num_string[] = "123456789012345678901234567890123456789012345678901234567890";

  BIGNUM *big_number = BN_new();
  //creeate from decimal string
  BN_dec2bn(&big_number, num_string);

  BN_print_fp(stdout,big_number);
  printf("\n");

  char *num_string_after = BN_bn2hex(big_number);
  printf("%s\n", num_string_after);
  printf("%s\n",  BN_bn2dec(big_number));

  // politely free OpenSSL generated heap structures
  OPENSSL_free(num_string_after);
  BN_free(big_number);

  return 0;
}
