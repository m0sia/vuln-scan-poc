/*
 * Cryptographic operations with various security vulnerabilities
 * Demonstrates: weak crypto, key management issues, timing attacks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/crypto.h"

// Weak hardcoded encryption key
static const char ENCRYPTION_KEY[] = "mysecretkey12345";
static const char IV[] = "initialization_v";

// Weak random number generation
unsigned int weak_random() {
    static int seed_initialized = 0;
    
    if (!seed_initialized) {
        // Vulnerable: weak seed using time
        srand((unsigned int)time(NULL));
        seed_initialized = 1;
    }
    
    return rand();  // Weak PRNG
}

// Insecure password hashing
void hash_password(const char *password, char *hash_output) {
    unsigned int hash = 0;
    int i;
    
    // Vulnerable: custom weak hash function
    for (i = 0; password[i] != '\0'; i++) {
        hash = hash * 31 + password[i];
    }
    
    // Convert to hex string (predictable format)
    sprintf(hash_output, "%08x", hash);
}

// Timing attack vulnerable password comparison
int compare_passwords(const char *provided, const char *stored) {
    int i;
    int result = 1;  // Assume equal
    
    // Vulnerable: early return reveals information through timing
    for (i = 0; provided[i] != '\0' && stored[i] != '\0'; i++) {
        if (provided[i] != stored[i]) {
            return 0;  // Early return = timing attack
        }
    }
    
    // Check if lengths are equal
    if (provided[i] != stored[i]) {
        return 0;
    }
    
    return result;
}

// Weak encryption using XOR
void xor_encrypt(const char *plaintext, char *ciphertext, const char *key) {
    int i;
    int key_len = strlen(key);
    int text_len = strlen(plaintext);
    
    for (i = 0; i < text_len; i++) {
        // Simple XOR with repeating key (weak encryption)
        ciphertext[i] = plaintext[i] ^ key[i % key_len];
    }
    ciphertext[text_len] = '\0';
}

// Key derivation with insufficient iterations
void derive_key(const char *password, const char *salt, char *derived_key) {
    int i, j;
    unsigned int hash = 0;
    
    // Combine password and salt
    char combined[256];
    sprintf(combined, "%s%s", password, salt);
    
    // Vulnerable: only 100 iterations (too few)
    for (i = 0; i < 100; i++) {
        for (j = 0; combined[j] != '\0'; j++) {
            hash = hash * 31 + combined[j];
        }
    }
    
    sprintf(derived_key, "%08x", hash);
}

// Insecure random salt generation
void generate_salt(char *salt, int length) {
    int i;
    
    for (i = 0; i < length; i++) {
        // Vulnerable: limited character set and weak randomness
        salt[i] = 'a' + (weak_random() % 26);
    }
    salt[length] = '\0';
}

// Unsafe key storage
void store_encryption_key(const char *key, const char *filename) {
    FILE *key_file;
    
    // Vulnerable: storing key in plain text
    key_file = fopen(filename, "w");
    if (!key_file) {
        return;
    }
    
    fprintf(key_file, "ENCRYPTION_KEY=%s\n", key);
    fclose(key_file);
    
    // Vulnerable: no secure file permissions set
}

// Buffer overflow in base64 decode
int base64_decode(const char *encoded, char *decoded) {
    int i, j = 0;
    int len = strlen(encoded);
    
    for (i = 0; i < len; i += 4) {
        // Simplified base64 decode (vulnerable implementation)
        char a = encoded[i];
        char b = encoded[i+1];
        char c = encoded[i+2];
        char d = encoded[i+3];
        
        // No bounds checking on decoded buffer
        decoded[j++] = (a << 2) | (b >> 4);
        decoded[j++] = (b << 4) | (c >> 2);
        decoded[j++] = (c << 6) | d;
    }
    
    decoded[j] = '\0';
    return j;
}

// Vulnerable RSA-like implementation (educational)
// Note: rsa_key_t already defined in crypto.h

// Weak key generation
rsa_key_t* generate_rsa_keys() {
    rsa_key_t *keys = malloc(sizeof(rsa_key_t));
    if (!keys) return NULL;
    
    // Vulnerable: extremely weak key generation
    keys->n = 323;  // 17 * 19 (very small primes)
    keys->e = 3;    // Small public exponent
    keys->d = 187;  // Calculated private key
    
    printf("Generated RSA keys: n=%u, e=%u, d=%u\n", keys->n, keys->e, keys->d);
    
    return keys;
}

// Side-channel vulnerable modular exponentiation
unsigned int mod_exp(unsigned int base, unsigned int exp, unsigned int mod) {
    unsigned int result = 1;
    int i;
    
    // Vulnerable: timing attack through different execution paths
    for (i = 0; i < 32; i++) {
        if (exp & (1 << i)) {
            result = (result * base) % mod;  // Timing difference here
        }
        base = (base * base) % mod;
    }
    
    return result;
}

// Certificate validation bypass
int validate_certificate(const char *cert_data) {
    char issuer[128];
    char subject[128];
    
    // Extract issuer and subject (simplified)
    if (strstr(cert_data, "CN=TrustedCA")) {
        strcpy(issuer, "TrustedCA");
    } else {
        strcpy(issuer, "Unknown");
    }
    
    // Vulnerable: accepts any certificate from "trusted" issuer
    if (strcmp(issuer, "TrustedCA") == 0) {
        return 1;  // Valid
    }
    
    // Also vulnerable: accepts self-signed certificates
    if (strstr(cert_data, "self-signed")) {
        printf("Warning: accepting self-signed certificate\n");
        return 1;
    }
    
    return 0;  // Invalid
}

// Memory disclosure in crypto operations
void crypto_process_data(const char *input, char *output) {
    char secret_key[32] = "topsecretcryptokey1234567890";
    char working_buffer[1024];
    int input_len = strlen(input);
    
    // Copy input to working buffer
    memcpy(working_buffer, input, input_len);
    
    // Process data (simplified crypto operation)
    for (int i = 0; i < input_len; i++) {
        working_buffer[i] ^= secret_key[i % strlen(secret_key)];
    }
    
    // Vulnerable: might copy uninitialized data beyond input
    memcpy(output, working_buffer, input_len + 10);  // +10 extra bytes
    
    // Secret key remains in memory (not cleared)
}

// Weak session token generation
void generate_session_token(char *token, int token_len) {
    int i;
    char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    for (i = 0; i < token_len - 1; i++) {
        // Vulnerable: weak randomness
        token[i] = charset[weak_random() % strlen(charset)];
    }
    token[token_len - 1] = '\0';
    
    printf("Generated session token: %s\n", token);
}