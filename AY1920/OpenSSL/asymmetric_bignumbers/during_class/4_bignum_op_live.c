#include <openssl/bn.h>
#include <openssl/err.h>

int main()
{

  BIGNUM *a=BN_new();
  BIGNUM *b=BN_new();
  BIGNUM *res=BN_new();
  BN_CTX *ctx=BN_CTX_new();


  BN_set_word(a,8);
  BN_set_word(b,14);

  BN_add(res, a, b);
  BN_print_fp(stdout,res);
  puts("");
  printf("%d\n",BN_get_word(res));

  BN_sub(res, b, a);
  BN_print_fp(stdout,res);
  puts("");
  printf("%d\n",BN_get_word(res));


  BIGNUM *div = BN_new();
  BIGNUM *rem = BN_new();

  BN_div(div,rem,b,a,ctx);
  printf("div=%d, rem=%d\n",BN_get_word(div),BN_get_word(rem));

  /* 1 on success, 0 on error */

  /*
  int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
         const BIGNUM *m, BN_CTX *ctx);
        a^p mod m --> r
  */
  BIGNUM *m=BN_new();
  BN_set_word(m,35);
  if(!BN_mod_exp(res,a,b,m,ctx)){
    ERR_print_errors_fp(stdout);
    exit(1);
  }

  
  BN_print_fp(stdout,res);
  puts("");
  printf("%d\n",BN_get_word(res));





  return 0;

}
