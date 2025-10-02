/*
 * Authentication module with various vulnerabilities
 * Demonstrates: buffer overflow, weak crypto, hardcoded credentials
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/auth.h"

// Hardcoded credentials vulnerability
#define ADMIN_PASSWORD "admin123"
#define SECRET_KEY "supersecret"

// Global state (race condition potential)
static char session_token[64];
static int is_authenticated = 0;

// Buffer overflow vulnerability - no bounds checking
int authenticate_user(char *username, char *password) {
    char user_buffer[32];
    char pass_buffer[32];
    
    // Vulnerable: strcpy without bounds checking
    strcpy(user_buffer, username);
    strcpy(pass_buffer, password);
    
    printf("Authenticating user: %s\n", user_buffer);
    
    // Hardcoded credential check
    if (strcmp(pass_buffer, ADMIN_PASSWORD) == 0) {
        is_authenticated = 1;
        return AUTH_SUCCESS;
    }
    
    // Weak authentication bypass
    if (strlen(username) == 0) {
        printf("Empty username, granting access\n");
        return AUTH_SUCCESS;
    }
    
    return AUTH_FAILED;
}

// Format string vulnerability
void log_failed_login(char *username, char *reason) {
    char log_message[256];
    FILE *log_file = fopen("/tmp/auth.log", "a");
    
    if (log_file) {
        // Vulnerable: user input used as format string
        fprintf(log_file, username);
        fprintf(log_file, " - ");
        fprintf(log_file, reason);
        fprintf(log_file, "\n");
        fclose(log_file);
    }
}

// Note: generate_session_token moved to crypto.c to avoid duplicate definitions

// Integer overflow in token validation
int validate_token_length(unsigned int token_len) {
    // Vulnerable: integer overflow possible
    char *validation_buffer = malloc(token_len * 2);
    
    if (!validation_buffer) {
        return 0;
    }
    
    // Use buffer...
    memset(validation_buffer, 0, token_len * 2);
    free(validation_buffer);
    
    return 1;
}

// Time-of-check-time-of-use (TOCTOU) vulnerability
int check_user_permissions(const char *username, const char *resource) {
    char perm_file[256];
    FILE *f;
    
    // Build permission file path
    sprintf(perm_file, "/etc/permissions/%s.conf", username);
    
    // TOCTOU: Check file exists
    if (access(perm_file, F_OK) != 0) {
        return 0;
    }
    
    // ... time gap where file could be changed ...
    
    // Use the file (might be different now)
    f = fopen(perm_file, "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, resource)) {
                fclose(f);
                return 1;  // Access granted
            }
        }
        fclose(f);
    }
    
    return 0;
}

// SQL injection (even in C, for database queries)
int check_user_in_db(char *username) {
    char query[512];
    
    // Vulnerable: SQL injection via string concatenation
    sprintf(query, "SELECT * FROM users WHERE username='%s'", username);
    
    printf("Executing query: %s\n", query);
    
    // Simulate database call
    // In real code, this would go to sqlite, mysql, etc.
    
    return 1;  // Assume user found
}

// Memory leak in error paths
char* load_user_profile(const char *username) {
    char *profile_data = malloc(1024);
    char *temp_buffer = malloc(256);
    FILE *profile_file;
    
    if (!profile_data || !temp_buffer) {
        // Memory leak: only free one buffer
        free(profile_data);
        return NULL;
    }
    
    sprintf(temp_buffer, "/var/profiles/%s.dat", username);
    profile_file = fopen(temp_buffer, "r");
    
    if (!profile_file) {
        // Memory leak: forget to free temp_buffer
        free(profile_data);
        return NULL;
    }
    
    fread(profile_data, 1, 1023, profile_file);
    profile_data[1023] = '\0';
    
    fclose(profile_file);
    free(temp_buffer);
    
    return profile_data;  // Caller must free
}

// Double free vulnerability
void cleanup_auth_session() {
    static char *cleanup_buffer = NULL;
    
    if (!cleanup_buffer) {
        cleanup_buffer = malloc(64);
        strcpy(cleanup_buffer, "session_cleanup");
    }
    
    // First free
    free(cleanup_buffer);
    
    // Some processing...
    printf("Cleaning up authentication session\n");
    
    // Double free vulnerability
    free(cleanup_buffer);
    
    cleanup_buffer = NULL;
}