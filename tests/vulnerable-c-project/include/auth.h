#ifndef AUTH_H
#define AUTH_H

#include <unistd.h>

// Authentication result codes
#define AUTH_SUCCESS 1
#define AUTH_FAILED 0

// Function declarations
int authenticate_user(char *username, char *password);
void log_failed_login(char *username, char *reason);
int validate_token_length(unsigned int token_len);
int check_user_permissions(const char *username, const char *resource);
int check_user_in_db(char *username);
char* load_user_profile(const char *username);
void cleanup_auth_session();

#endif // AUTH_H