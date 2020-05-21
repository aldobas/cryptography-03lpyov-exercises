#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

#define KEY_LENGTH  2048
#define ERR_SIZE 130

int main(void) {


    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char *pri_key;           // Private key
    char *pub_key;           // Public key
    RSA  *keypair;             //RSA data structure


    char msg[KEY_LENGTH/8];  // Message to encrypt
    char err[ERR_SIZE];      // Buffer for any error messages (130 by openssl specs)




}
