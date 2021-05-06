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

    // Generate key pair
    printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    BIGNUM *bn_pub_exp = BN_new();
    BN_set_word(bn_pub_exp,RSA_F4);
    keypair = RSA_new();
    RSA_generate_key_ex(keypair, KEY_LENGTH, bn_pub_exp, NULL);


    // To get the PEM RSA data structure in memory
    // NOTE: in alternative use a non-bio version of functions to stdout to print the keys
    BIO *pri_bio = BIO_new(BIO_s_mem());
    BIO *pub_bio = BIO_new(BIO_s_mem());


    PEM_write_bio_RSAPrivateKey(pri_bio, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub_bio, keypair);

    //count the character actually written into the BIO object
    pri_len = BIO_pending(pri_bio);
    pub_len = BIO_pending(pub_bio);

    // allocate a standard string
    pri_key = (char*)malloc(pri_len + 1); //room for the '\0'
    pub_key = (char*)malloc(pub_len + 1); //room for the '\0'

    BIO_read(pri_bio, pri_key, pri_len);
    BIO_read(pub_bio, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';


    //print the PEM strings
    printf("\n%s\n%s\n", pri_key, pub_key);
    printf("done.\n");

    // Get the message to encrypt
    printf("Insert the message to encrypt: ");
    fgets(msg, KEY_LENGTH-1, stdin);
    // replace the \n
    msg[strlen(msg)-1] = '\0';

    // Encrypt the message
    char *encrypted_data = NULL;    // Encrypted message
    int encrypted_data_len;

    // int RSA_size(const RSA *rsa);
    encrypted_data = (char*)malloc(RSA_size(keypair));

    /*
    int RSA_public_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);

    RSA_public_encrypt() returns the size of the encrypted data (i.e.,
    RSA_size(rsa)). RSA_private_decrypt() returns the size of the recovered
    plaintext. A return value of 0 is not an error and means only that the plaintext was empty.

    On error, -1 is returned; the error codes can be obtained by ERR_get_error(3).
    */

    if((encrypted_data_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg,
                                        (unsigned char*)encrypted_data,
                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        goto free_allocated_memory;
    }

    // save the message on a file
    FILE *out = fopen("out.bin", "w");
    //size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
    //sizeof(*encrypted_data) = sizeof(char) = 1 byte
    fwrite(encrypted_data, sizeof(*encrypted_data),  RSA_size(keypair), out);
    fclose(out);
    printf("Encrypted message written to file.\n");
    free(encrypted_data);
    encrypted_data = NULL;

/*********************************************************************/

    // Read it back
    printf("Reading encrypted message and attempting decryption...\n");
    encrypted_data = (char*)malloc(RSA_size(keypair));
    out = fopen("out.bin", "r");
    fread(encrypted_data, sizeof(*encrypted_data), RSA_size(keypair), out);
    fclose(out);


    // Decrypt it
    char *decrypted_data;    // Decrypted message
    decrypted_data = (char*)malloc(encrypted_data_len);

/*
    int RSA_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);

    Error management is the same and the _encrypt function
*/

    if(RSA_private_decrypt(encrypted_data_len, (unsigned char*)encrypted_data,
                          (unsigned char*)decrypted_data,
                          keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        goto free_allocated_memory;
    }
    printf("Decrypted message: %s\n", decrypted_data);

    free_allocated_memory:
      RSA_free(keypair);
      BIO_free_all(pub_bio);
      BIO_free_all(pri_bio);
      free(pri_key);
      free(pub_key);
      free(encrypted_data);
      free(decrypted_data);


    return 0;
}
