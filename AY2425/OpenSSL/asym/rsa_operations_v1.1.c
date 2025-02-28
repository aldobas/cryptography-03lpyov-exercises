#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

#define KEY_LENGTH  2048


void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(void) {


    size_t pri_len;// Length of private key
    size_t pub_len;// Length of public key
    RSA  *keypair; //RSA data structure


    // Message to encrypt, MUST be shorter than the RSA key length - padding
    char msg[] = "message to encrypt with RSA";  



    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    // Generate key pair
    printf("Generating a fresh RSA (%d bits) keypair...\n", KEY_LENGTH);
    BIGNUM *bn_pub_exp = BN_new();
    BN_set_word(bn_pub_exp,RSA_F4);
    
    keypair = RSA_new();
    if(!RSA_generate_key_ex(keypair, KEY_LENGTH, bn_pub_exp, NULL))
        handle_errors();


    // Encrypt the message
 
    /*
    int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    RSA_public_encrypt() returns the size of the encrypted data (i.e., RSA_size(rsa)). 
    RSA_private_decrypt() returns the size of the recovered plaintext. 
    A return value of 0 is not an error and means only that the plaintext was empty. On error, -1 is returned; the error codes can be obtained by ERR_get_error(3).
    */

    // int RSA_size(const RSA *rsa);
    int encrypted_data_len;
    unsigned char encrypted_data[RSA_size(keypair)];


    if((encrypted_data_len = RSA_public_encrypt(strlen(msg)+1, msg, encrypted_data, keypair, RSA_PKCS1_OAEP_PADDING)) == -1) 
            handle_errors();



    // save the message on a file
    FILE *out = fopen("out.bin", "w");
    if(fwrite(encrypted_data, 1,  RSA_size(keypair), out) < RSA_size(keypair))
        handle_errors();
    fclose(out);
    
    printf("Encrypted message written to file.\n");
    

/*********************************************************************/

    // Read it back
    printf("Reading the encrypted message from file and attempting decryption...\n");
    FILE *in = fopen("out.bin", "r");
    if (fread(encrypted_data, 1, RSA_size(keypair), in) != RSA_size(keypair))
        handle_errors();
    fclose(in);


    // Decrypt it
    unsigned char decrypted_data[RSA_size(keypair)];
/*
    int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    Error management is the same as the _encrypt function
*/

    if(RSA_private_decrypt(encrypted_data_len, (unsigned char*)encrypted_data,
                          (unsigned char*)decrypted_data,
                          keypair, RSA_PKCS1_OAEP_PADDING) == -1) 
            handle_errors();

    printf("Decrypted message: %s\n", decrypted_data);

    RSA_free(keypair);

    // completely free all the cipher data
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */  
    ERR_free_strings();


    return 0;
}
