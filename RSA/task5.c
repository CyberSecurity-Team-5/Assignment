#include <openssl/bn.h>
#include <stdio.h>

void printBN(char *msg, BIGNUM * a){
    // Convert the BIGNUM to number string 
        char * number_str = BN_bn2hex(a);
    // Print out the number string 
        printf("%s %s\n", msg, number_str);
    // Free the dynamically allocated memory 
        OPENSSL_free(number_str);

    }

    int main(){
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *n = BN_new();
        BIGNUM *e = BN_new();

        BIGNUM *m = BN_new();
        BIGNUM *s = BN_new();
        BIGNUM *m1 = BN_new();



        //Assign hex values to our variables
        BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
        BN_hex2bn(&e, "010001");
        BN_hex2bn(&m, "4c61756e63682061206d6973736c652e");
        BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");


        BN_mod_exp(m1, s, e, n, ctx);
        printBN("Message 1 = ", m1);
        printBN("message: ", m);
        printf("%s",BN_cmp(m1,m) == 0? "Alice's signature" : "Not Alice's signature");

        BN_CTX_free(ctx);

        return 0;

    }