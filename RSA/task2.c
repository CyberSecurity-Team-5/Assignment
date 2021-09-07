#include <stdio.h>
#include <openssl/bn.h>

int main(int argc, char const *argv[]) {

  //Creating ctx to temporary store those BIGNUM
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *n = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *M = BN_new();
  BIGNUM *c = BN_new();

  //Assign convert hexdecimal value into BIGNUM
  BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&e,"010001");
  BN_hex2bn(&M,"4120746f702073656372657421");

  //To encrypt message m(<n),compute
  // c = m^e mod n
  BN_mod_exp(c,M,e,n,ctx);
  //convert BIGNUM back to hexdecimal.
  char * number_str = BN_bn2hex(c);
  printf("%s\n",number_str);

  //Free the dynamic memory
  OPENSSL_free(n);
  OPENSSL_free(e);
  OPENSSL_free(M);
  OPENSSL_free(c);

  return 0;
}
