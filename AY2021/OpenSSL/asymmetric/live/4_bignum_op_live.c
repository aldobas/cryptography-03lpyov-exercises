#include <openssl/bn.h>
#include <openssl/err.h>

int main()
{

  BIGNUM *a=BN_new();
  BIGNUM *b=BN_new();
  BIGNUM *res=BN_new();
  BN_CTX *ctx=BN_CTX_new();


  // a and b
  BN_set_word(a,234);
  BN_set_word(b,23);


  // a + b
  BN_add(res,a,b);
  printf("sum = %s\n",BN_bn2dec(res));

  // a - b
  BN_sub(res,a,b);
  printf("diff = %s\n",BN_bn2dec(res));



  // a:b and a mod b
  BIGNUM *div = BN_new();
  BIGNUM *rem = BN_new();

  BN_div(div,rem,a,b,ctx);
  printf("div = %s\n",BN_bn2dec(div));
  printf("rem = %s\n",BN_bn2dec(rem));

  /*
  int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
         const BIGNUM *m, BN_CTX *ctx);
        a^p mod m --> r
  */
  BIGNUM *exp = BN_new();
  BIGNUM *modulus = BN_new();
  BN_set_word(modulus, 14);
  BN_mod_exp(exp, a, b, modulus, ctx);
  printf("exp = %s\n",BN_bn2dec(exp));




  //free all


  BN_free(a);
  BN_free(b);
  BN_free(res);
  BN_free(div);
  BN_free(rem);
  BN_free(exp);
  BN_free(modulus);



  return 0;

}
