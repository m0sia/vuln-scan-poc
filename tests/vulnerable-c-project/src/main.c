/*
 * Main application demonstrating vulnerable code patterns
 * Links together all vulnerable modules for comprehensive testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/auth.h"
#include "../include/fileops.h"
#include "../include/network.h"
#include "../include/crypto.h"

#define MAX_INPUT_SIZE 256

// Global buffer for user input (poor practice)
char global_input_buffer[1024];

// Unsafe command line argument processing
void process_arguments(int argc, char *argv[]) {
    char command_buffer[512];
    int i;
    
    printf("Processing %d arguments:\n", argc);
    
    for (i = 1; i < argc; i++) {
        // Vulnerable: no bounds checking on argument length
        strcat(command_buffer, argv[i]);
        strcat(command_buffer, " ");
        
        printf("Arg %d: %s\n", i, argv[i]);
    }
    
    printf("Combined arguments: %s\n", command_buffer);
}

// Demonstrate authentication vulnerabilities
void demo_auth_vulnerabilities() {
    char username[64];
    char password[64];
    char *profile_data;
    
    printf("\n=== Authentication Module Demo ===\n");
    
    // Simulate user input (in real app, this would come from network/stdin)
    strcpy(username, "admin");
    strcpy(password, "admin123");
    
    // Test authentication
    if (authenticate_user(username, password)) {
        printf("Authentication successful!\n");
        
        // Generate session token
        char token[64];
        generate_session_token(token, sizeof(token));
        printf("Session token: %s\n", token);
        
        // Load user profile (potential memory leak)
        profile_data = load_user_profile(username);
        if (profile_data) {
            printf("Profile loaded: %s\n", profile_data);
            free(profile_data);  // Remember to free
        }
    } else {
        // Log failed login (format string vulnerability)
        log_failed_login(username, "Invalid password");
    }
    
    // Test dangerous cleanup
    cleanup_auth_session();
}

// Demonstrate file operation vulnerabilities  
void demo_file_vulnerabilities() {
    char filename[128];
    char *temp_file;
    
    printf("\n=== File Operations Module Demo ===\n");
    
    // Test path traversal
    strcpy(filename, "../../../etc/passwd");
    printf("Attempting to read: %s\n", filename);
    read_user_file(filename);
    
    // Test unsafe temporary file creation
    temp_file = create_temp_file("demo");
    if (temp_file) {
        printf("Created temp file: %s\n", temp_file);
        
        // Test file upload with injection
        char upload_content[] = "Test file content\nFAKE_LOG_ENTRY: Admin access granted\n";
        handle_file_upload("../important.txt", upload_content, strlen(upload_content));
        
        free(temp_file);
    }
    
    // Test directory traversal
    list_directory_contents("../../../tmp");
    
    // Test archive extraction (zip bomb potential)
    extract_archive("/tmp/suspicious.tar.gz", "/tmp/extracted");
}

// Demonstrate network vulnerabilities
void demo_network_vulnerabilities() {
    char http_request[1024];
    char packet_data[2048];
    char *receive_buffer;
    
    printf("\n=== Network Module Demo ===\n");
    
    // Simulate HTTP request processing
    strcpy(http_request, "GET /admin/../../../etc/passwd HTTP/1.1\r\nHost: vulnerable-server.com\r\nCookie: session=admin; role=user\r\n\r\n");
    parse_http_request(http_request);
    
    // Test packet processing with overflow
    memset(packet_data, 'A', 1500);  // Large packet
    packet_data[1500] = '\0';
    process_network_packet(packet_data, 1500);
    
    // Test integer overflow in buffer allocation
    receive_buffer = allocate_receive_buffer(0x10000, 0x10000);  // Will overflow
    if (receive_buffer) {
        printf("Allocated receive buffer\n");
        free(receive_buffer);
    }
    
    // Test hostname validation with injection
    validate_hostname("evil.com; rm -rf /");
    
    // Test logging with format string
    log_network_event("192.168.1.100", "User %s logged in from %s");
}

// Demonstrate crypto vulnerabilities
void demo_crypto_vulnerabilities() {
    char password[] = "mysecretpassword";
    char hash[32];
    char salt[16];
    char derived_key[32];
    char token[64];
    rsa_key_t *keys;
    
    printf("\n=== Cryptographic Module Demo ===\n");
    
    // Test weak password hashing
    hash_password(password, hash);
    printf("Password hash: %s\n", hash);
    
    // Test weak salt generation
    generate_salt(salt, 15);
    printf("Generated salt: %s\n", salt);
    
    // Test weak key derivation
    derive_key(password, salt, derived_key);
    printf("Derived key: %s\n", derived_key);
    
    // Test weak RSA key generation
    keys = generate_rsa_keys();
    if (keys) {
        printf("RSA keys generated\n");
        free(keys);
    }
    
    // Test weak session token generation
    generate_session_token(token, 32);
    printf("Session token: %s\n", token);
    
    // Test timing attack vulnerable comparison
    if (compare_passwords("admin123", "admin123")) {
        printf("Password comparison: MATCH\n");
    } else {
        printf("Password comparison: NO MATCH\n");
    }
    
    // Test certificate validation bypass
    char fake_cert[] = "CN=TrustedCA,O=Evil Corp,self-signed=true";
    if (validate_certificate(fake_cert)) {
        printf("Certificate validation: PASSED (should fail!)\n");
    }
}

// Stack buffer overflow demonstration
void demonstrate_stack_overflow(char *user_input) {
    char local_buffer[64];
    
    printf("Processing user input of length: %zu\n", strlen(user_input));
    
    // Classic stack buffer overflow
    strcpy(local_buffer, user_input);
    
    printf("Processed input: %s\n", local_buffer);
}

// Heap overflow demonstration
void demonstrate_heap_overflow() {
    char *heap_buffer = malloc(64);
    char large_input[128];
    
    if (!heap_buffer) return;
    
    // Fill input with data larger than buffer
    memset(large_input, 'X', 127);
    large_input[127] = '\0';
    
    // Heap overflow
    strcpy(heap_buffer, large_input);
    
    printf("Heap buffer contains: %.64s...\n", heap_buffer);
    
    free(heap_buffer);
}

int main(int argc, char *argv[]) {
    printf("Vulnerable C Application - Security Testing Suite\n");
    printf("================================================\n");
    
    // Process command line arguments unsafely
    process_arguments(argc, argv);
    
    // Run vulnerability demonstrations
    demo_auth_vulnerabilities();
    demo_file_vulnerabilities();
    demo_network_vulnerabilities();
    demo_crypto_vulnerabilities();
    
    // Demonstrate buffer overflows
    char overflow_input[200];
    memset(overflow_input, 'A', 199);
    overflow_input[199] = '\0';
    
    printf("\n=== Buffer Overflow Demos ===\n");
    demonstrate_stack_overflow(overflow_input);
    demonstrate_heap_overflow();
    
    // Use global buffer unsafely
    if (argc > 1) {
        strcpy(global_input_buffer, argv[1]);  // Potential overflow
        printf("Global buffer contains: %s\n", global_input_buffer);
    }
    
    printf("\nApplication completed. Check for vulnerabilities!\n");
    return 0;
}