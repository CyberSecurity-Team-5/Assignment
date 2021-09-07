#include <stdio.h>
#include <openssl/bn.h>

// Question : Using the given prime number p,q,e to create a public key and use the public key to calculate the private key d.

void printBN(char *msg, BIGNUM *a, BIGNUM *b)
{
    char * number_str1 = BN_bn2hex(a);

    char * number_str2 = BN_bn2hex(b);

    printf("%s \n %s \n %s \n",msg,number_str1,number_str2);

    OPENSSL_free(number_str1);
    OPENSSL_free(number_str2);

}

int main(int argc, char const *argv[]) {

  //BN_CTX is a structure to create to hold BIGNUM temporary variables's used by library function.
  BN_CTX *ctx = BN_CTX_new();

  //Initalize a BIGNUM p,q,e,n variables
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();
  BIGNUM *n = BN_new();

  BIGNUM *z = BN_new();
  //Initalize p and q subtract 1, so we could use to find what z is.
  BIGNUM *p_sub1 = BN_new();
  BIGNUM *q_sub1 = BN_new();

  BIGNUM *d = BN_new();
  //Assign hex-values that was given into p,q,e.
  BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e,"0D88C3");
  //n = p * q
  BN_mul(n,p,q,ctx);
  // printBN("Value n = ",n,e);


  BN_sub(p_sub1,p,BN_value_one());
  BN_sub(q_sub1,q,BN_value_one());
  // z = (p - 1)(q - 1)
  BN_mul(z,p_sub1,q_sub1,ctx);

  //Nowe we have, e and z, we could find d by using this equation.
  // ed mod z = 1
  BN_mod_inverse(d, e, z,ctx);
  char * number = BN_bn2hex(d);
  printf("%s\n",number);

  OPENSSL_free(p);
  OPENSSL_free(q);
  OPENSSL_free(e);
  OPENSSL_free(n);
  OPENSSL_free(z);
  OPENSSL_free(p_sub1);
  OPENSSL_free(q_sub1);
  OPENSSL_free(d);

  return 0;
}
