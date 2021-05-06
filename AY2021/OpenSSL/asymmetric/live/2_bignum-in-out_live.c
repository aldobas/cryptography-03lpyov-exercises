#include <stdio.h>
#include <openssl/bn.h>

int main ()
{

  char num_string[] = "123456789012345678901234567890123456789012345678901234567890";

  BIGNUM *big_number = BN_new();

  //BN_dec2bn
  BN_dec2bn(&big_number,num_string);
  BN_print_fp(stdout,big_number);
  puts("");

  //BN_bn2hex
  char *hex_str = BN_bn2hex(big_number);
  printf("hex str = %s\n",hex_str);



  // free all the dynamically allocated memory

  BN_free(big_number);
  OPENSSL_free(hex_str);

  return 0;

}
