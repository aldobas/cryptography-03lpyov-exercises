#include <openssl/bn.h>
#include <openssl/err.h>

int main()
{
  // a newly instantiated BIGNUM is initialized to 0
  BIGNUM *a=BN_new();
  BN_set_word(a,8);
  
  
  BIGNUM *b=BN_new();
  BN_set_word(b,14);

/* https://www.openssl.org/docs/man1.0.2/man3/BN_add.html */

  // add two numbers
  BIGNUM *res=BN_new();
  BN_add(res,a,b);
  // BN_add(a,a,b);
  BN_print_fp(stdout,res);
  puts("");
  printf("%lu\n",BN_get_word(res));

  //subtraction
  BN_sub(res,b,a);
  printf("%lu\n",BN_get_word(res));


  // integer division
  BIGNUM *div=BN_new();
  BIGNUM *rem=BN_new();

  // a context is needed to optimize some operations
  BN_CTX *ctx=BN_CTX_new();
  BN_div(div,rem,b,a,ctx);
  printf("div=%lu, rem=%lu\n",BN_get_word(div),BN_get_word(rem));

  /*
  For all functions, 1 is returned for success, 0 on error.
  */

  /*
  int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
         const BIGNUM *m, BN_CTX *ctx);
  */
  BIGNUM *m=BN_new();
  BN_set_word(m,35);
  // a^b mod m
  if (!BN_mod_exp(res,a,b,m,ctx)) {
    ERR_print_errors_fp(stdout);
    exit(1);
  }

  BN_print_fp(stdout,res);
  puts("");

  /*
  int BN_cmp(BIGNUM *a, BIGNUM *b);
  int BN_ucmp(BIGNUM *a, BIGNUM *b);
  */
  int cmp_result;
  cmp_result = BN_cmp(a,b);
  if(cmp_result == 0)
    printf("=\n");
  else if (cmp_result <0)
    printf("<\n");
  else
    printf(">\n");

  return 0;
}
