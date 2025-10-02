/*
 * Network operations module with various network security vulnerabilities
 * Demonstrates: buffer overflow in network code, unsafe string handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/network.h"

#define BUFFER_SIZE 1024
#define MAX_CONNECTIONS 10

// Global connection pool (race conditions possible)
static int connection_pool[MAX_CONNECTIONS];
static int pool_count = 0;

// Buffer overflow in network packet processing
int process_network_packet(char *packet_data, size_t data_len) {
    char processing_buffer[512];
    char header_buffer[64];
    
    // Vulnerable: no bounds checking on data_len
    memcpy(processing_buffer, packet_data, data_len);
    
    // Extract header (assume first 32 bytes)
    memcpy(header_buffer, packet_data, 32);
    
    printf("Processing packet with %zu bytes\n", data_len);
    printf("Header: %s\n", header_buffer);  // No null termination guaranteed
    
    return 0;
}

// Unsafe HTTP request parsing
void parse_http_request(char *request) {
    char method[16];
    char url[256];
    char version[16];
    char *line, *token;
    
    // Get first line
    line = strtok(request, "\r\n");
    if (!line) return;
    
    // Parse method, URL, version
    token = strtok(line, " ");
    if (token) {
        strcpy(method, token);  // Vulnerable: no bounds check
    }
    
    token = strtok(NULL, " ");
    if (token) {
        strcpy(url, token);     // Vulnerable: no bounds check
    }
    
    token = strtok(NULL, " ");
    if (token) {
        strcpy(version, token); // Vulnerable: no bounds check
    }
    
    printf("Method: %s, URL: %s, Version: %s\n", method, url, version);
}

// Format string vulnerability in logging
void log_network_event(char *client_ip, char *event_msg) {
    FILE *log_file = fopen("/var/log/network.log", "a");
    char timestamp[64];
    time_t now = time(NULL);
    
    if (!log_file) return;
    
    strcpy(timestamp, ctime(&now));
    timestamp[strlen(timestamp)-1] = '\0';  // Remove newline
    
    fprintf(log_file, "[%s] %s: ", timestamp, client_ip);
    
    // Vulnerable: user-controlled format string
    fprintf(log_file, event_msg);
    
    fprintf(log_file, "\n");
    fclose(log_file);
}

// Integer overflow in buffer allocation
char* allocate_receive_buffer(unsigned int packet_count, unsigned int packet_size) {
    char *buffer;
    size_t total_size;
    
    // Vulnerable: integer overflow in multiplication
    total_size = packet_count * packet_size;
    
    printf("Allocating buffer for %u packets of %u bytes each\n", 
           packet_count, packet_size);
    
    buffer = malloc(total_size);
    if (!buffer) {
        printf("Failed to allocate %zu bytes\n", total_size);
        return NULL;
    }
    
    memset(buffer, 0, total_size);
    return buffer;
}

// Unsafe hostname validation
int validate_hostname(const char *hostname) {
    char safe_hostname[64];
    char command[256];
    
    // Attempt sanitization but incomplete
    strncpy(safe_hostname, hostname, sizeof(safe_hostname) - 1);
    safe_hostname[sizeof(safe_hostname) - 1] = '\0';
    
    // Command injection vulnerability
    sprintf(command, "nslookup %s", safe_hostname);
    
    printf("Validating hostname with: %s\n", command);
    return system(command);  // Dangerous: command injection
}

// Unsafe URL parsing
void parse_url(const char *url, char *host, char *path, int *port) {
    char url_copy[512];
    char *proto, *host_part, *path_part, *port_str;
    
    // Copy URL for parsing
    strcpy(url_copy, url);  // Vulnerable: no bounds check
    
    // Parse protocol
    proto = strtok(url_copy, "://");
    host_part = strtok(NULL, "/");
    path_part = strtok(NULL, "");
    
    if (!host_part) return;
    
    // Check for port
    port_str = strchr(host_part, ':');
    if (port_str) {
        *port_str = '\0';
        port_str++;
        *port = atoi(port_str);  // No validation
    } else {
        *port = 80;  // Default
    }
    
    strcpy(host, host_part);  // Vulnerable: no bounds check
    
    if (path_part) {
        strcpy(path, path_part);  // Vulnerable: no bounds check
    } else {
        strcpy(path, "/");
    }
}

// Cookie parsing with buffer overflow
void parse_cookies(const char *cookie_header) {
    char cookies[1024];
    char name[128];
    char value[256];
    char *cookie, *eq_sign;
    
    // Copy cookie header
    strcpy(cookies, cookie_header);  // Vulnerable: no bounds check
    
    // Parse cookies
    cookie = strtok(cookies, ";");
    while (cookie) {
        // Skip whitespace
        while (*cookie == ' ') cookie++;
        
        eq_sign = strchr(cookie, '=');
        if (eq_sign) {
            *eq_sign = '\0';
            strcpy(name, cookie);      // Vulnerable: no bounds check
            strcpy(value, eq_sign + 1); // Vulnerable: no bounds check
            
            printf("Cookie: %s = %s\n", name, value);
        }
        
        cookie = strtok(NULL, ";");
    }
}

// Unsafe network address handling
void handle_client_connection(int client_socket) {
    char buffer[1024];
    char response[2048];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    ssize_t bytes_received;
    
    // Get client address
    getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len);
    
    // Receive data
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        close(client_socket);
        return;
    }
    
    // Null terminate (but no bounds check on bytes_received)
    buffer[bytes_received] = '\0';
    
    printf("Received %zd bytes from client\n", bytes_received);
    
    // Process request (vulnerable functions)
    parse_http_request(buffer);
    
    // Build response with potential overflow
    sprintf(response, "HTTP/1.1 200 OK\r\nContent-Length: %zd\r\n\r\n%s", 
            strlen(buffer), buffer);
    
    send(client_socket, response, strlen(response), 0);
    close(client_socket);
}

// Connection pool management with race conditions
int add_connection_to_pool(int socket_fd) {
    // Race condition: multiple threads could modify pool_count
    if (pool_count >= MAX_CONNECTIONS) {
        return -1;  // Pool full
    }
    
    connection_pool[pool_count] = socket_fd;
    pool_count++;  // Not atomic
    
    printf("Added connection %d to pool, total: %d\n", socket_fd, pool_count);
    return 0;
}

// Unsafe server setup
int setup_server(int port) {
    int server_socket;
    struct sockaddr_in server_addr;
    int opt = 1;
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Set socket options
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
    server_addr.sin_port = htons(port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        return -1;
    }
    
    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        return -1;
    }
    
    printf("Server listening on port %d\n", port);
    return server_socket;
}