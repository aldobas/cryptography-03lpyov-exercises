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


        // Message to encrypt, MUST be shorter than the RSA key length - padding
    char msg[] = "message to encrypt with RSA";  



    // Generate key pair
    printf("Generating a fresh RSA (%d bits) keypair...\n", KEY_LENGTH);
    
    EVP_PKEY *keypair = NULL;
    int bits = 2048;
    if((keypair = EVP_RSA_gen(bits)) == NULL ) 
        handle_errors();
    
    
    
    // Encrypt the message


    // Create and initialize a new context for encryption.
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
        handle_errors();
    }
    // Specific configurations can be performed through the initialized context
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_errors();
    }

 
    // Determine the size of the output
    size_t encrypted_msg_len;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &encrypted_msg_len, msg, strlen(msg)) <= 0) {
        handle_errors();
    }


    unsigned char encrypted_msg[encrypted_msg_len];
    if (EVP_PKEY_encrypt(enc_ctx, encrypted_msg, &encrypted_msg_len, msg, strlen(msg)) <= 0) {
        handle_errors();
    }


    // save the message to a file
    FILE *fout = fopen("out.bin", "w");
    if(fwrite(encrypted_msg, 1,  encrypted_msg_len, fout) < EVP_PKEY_size(keypair))
        handle_errors();
    fclose(fout);
    
    printf("Encrypted message written to file.\n");
    

/*********************************************************************/

    // Read it back
    printf("Reading the encrypted message from file and attempting decryption...\n");
    FILE *fin = fopen("out.bin", "r");
    if (fread(encrypted_msg, 1, encrypted_msg_len, fin) != EVP_PKEY_size(keypair))
        handle_errors();
    fclose(fin);


    // Decrypt it


    EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
        handle_errors();
    }

    if (EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handle_errors();
    }

    size_t decrypted_msg_len;
    
    if (EVP_PKEY_decrypt(dec_ctx, NULL, &decrypted_msg_len, encrypted_msg, encrypted_msg_len) <= 0) {
        handle_errors();
    }

    unsigned char decrypted_msg[decrypted_msg_len+1];

    if (EVP_PKEY_decrypt(dec_ctx, decrypted_msg, &decrypted_msg_len, encrypted_msg, encrypted_msg_len) <= 0) {
        handle_errors();
    }

    decrypted_msg[decrypted_msg_len] = '\0';
    printf("Decrypted Plaintext is:\n-->%s\n",decrypted_msg);
    // BIO_dump_fp(stdout, (const char*) decrypted_msg, decrypted_msg_len);


    EVP_PKEY_free(keypair);


    return 0;
}
