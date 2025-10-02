#ifndef CRYPTO_H
#define CRYPTO_H

// RSA key structure
typedef struct {
    unsigned int n;
    unsigned int e;
    unsigned int d;
} rsa_key_t;

// Function declarations
unsigned int weak_random();
void hash_password(const char *password, char *hash_output);
int compare_passwords(const char *provided, const char *stored);
void xor_encrypt(const char *plaintext, char *ciphertext, const char *key);
void derive_key(const char *password, const char *salt, char *derived_key);
void generate_salt(char *salt, int length);
void store_encryption_key(const char *key, const char *filename);
int base64_decode(const char *encoded, char *decoded);
rsa_key_t* generate_rsa_keys();
unsigned int mod_exp(unsigned int base, unsigned int exp, unsigned int mod);
int validate_certificate(const char *cert_data);
void crypto_process_data(const char *input, char *output);
void generate_session_token(char *token, int token_len);

#endif // CRYPTO_H