#include <openssl/bn.h>
#include <stdio.h>

void printBN(char *msg, BIGNUM *a) {
    // Convert the BIGNUM to number string
    char *number_str = BN_bn2hex(a);
    // Print out the number string
    printf("%s %s\n", msg, number_str);
    // Free the dynamically allocated memory
    OPENSSL_free(number_str);
}
int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();

    BIGNUM *m = BN_new();
    BIGNUM *m1 = BN_new();

    BIGNUM *s = BN_new();
    BIGNUM *s1 = BN_new();

    //Assign a value from a hex number string 
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    //I owe you $2000
    BN_hex2bn(&m, "49206f776520796f75202432303030");
    //I owe you $3000
    BN_hex2bn(&m1, "49206f776520796f75202433303030");

    //sign message
    BN_mod_exp(s, m, d, n, ctx);
    BN_mod_exp(s1, m1, d, n, ctx);

    printBN("signature of message 1 = ", s);
    printBN("signature of message 2 = ", s1);

    BN_CTX_free(ctx);

    return 0;
}  