/*
 * File operations module with path traversal and unsafe file handling
 * Demonstrates: path traversal, symlink attacks, file race conditions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "../include/fileops.h"

#define MAX_PATH_LEN 512
#define UPLOAD_DIR "/tmp/uploads"

// Path traversal vulnerability
int read_user_file(const char *filename) {
    char filepath[MAX_PATH_LEN];
    FILE *file;
    char buffer[1024];
    
    // Vulnerable: no validation of filename for path traversal
    sprintf(filepath, "%s/%s", UPLOAD_DIR, filename);
    
    printf("Reading file: %s\n", filepath);
    
    file = fopen(filepath, "r");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }
    
    // Read and display file contents
    while (fgets(buffer, sizeof(buffer), file)) {
        printf("%s", buffer);
    }
    
    fclose(file);
    return 0;
}

// Unsafe temporary file creation
char* create_temp_file(const char *prefix) {
    char *temp_path = malloc(256);
    int fd;
    
    if (!temp_path) return NULL;
    
    // Vulnerable: predictable temporary file names
    sprintf(temp_path, "/tmp/%s_%d.tmp", prefix, getpid());
    
    // Race condition: file could be created by attacker between check and use
    if (access(temp_path, F_OK) == 0) {
        printf("Temp file already exists, removing\n");
        unlink(temp_path);
    }
    
    // Create file (but attacker could create symlink here)
    fd = open(temp_path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        free(temp_path);
        return NULL;
    }
    
    close(fd);
    return temp_path;  // Caller must free
}

// Directory traversal in file listing
void list_directory_contents(const char *user_path) {
    char full_path[512];
    char command[1024];
    
    // Vulnerable: no validation of user_path
    sprintf(full_path, "/var/data/%s", user_path);
    
    // Command injection vulnerability
    sprintf(command, "ls -la '%s'", full_path);
    
    printf("Executing: %s\n", command);
    system(command);  // Dangerous: command injection possible
}

// Unsafe file copy with buffer overflow
int copy_file(const char *src, const char *dst) {
    FILE *source, *dest;
    char buffer[512];  // Fixed size buffer
    size_t bytes_read;
    
    source = fopen(src, "rb");
    if (!source) {
        return -1;
    }
    
    dest = fopen(dst, "wb");
    if (!dest) {
        fclose(source);
        return -1;
    }
    
    // Vulnerable: no size checking, could overflow buffer
    while ((bytes_read = fread(buffer, 1, sizeof(buffer) + 100, source)) > 0) {
        fwrite(buffer, 1, bytes_read, dest);
    }
    
    fclose(source);
    fclose(dest);
    return 0;
}

// File permission bypass
int write_to_protected_file(const char *filename, const char *data) {
    char backup_name[512];
    int fd;
    
    // Create backup with predictable name
    sprintf(backup_name, "%s.backup", filename);
    
    // Vulnerable: doesn't check if backup already exists (symlink attack)
    fd = open(backup_name, O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        return -1;
    }
    
    // Write data without length validation
    write(fd, data, strlen(data));
    close(fd);
    
    // Atomic move (but backup was already vulnerable)
    if (rename(backup_name, filename) != 0) {
        unlink(backup_name);
        return -1;
    }
    
    return 0;
}

// Unsafe archive extraction
int extract_archive(const char *archive_path, const char *extract_to) {
    char command[1024];
    char safe_path[256];
    
    // Attempt to sanitize but incomplete
    strncpy(safe_path, extract_to, sizeof(safe_path) - 1);
    safe_path[sizeof(safe_path) - 1] = '\0';
    
    // Still vulnerable to command injection
    sprintf(command, "tar -xf '%s' -C '%s'", archive_path, safe_path);
    
    printf("Extracting with command: %s\n", command);
    
    // Zip bomb and path traversal vulnerabilities
    return system(command);
}

// Log file injection
void log_file_operation(const char *operation, const char *filename) {
    FILE *log_file;
    char log_entry[1024];
    
    log_file = fopen("/var/log/fileops.log", "a");
    if (!log_file) return;
    
    // Vulnerable: log injection via filename
    sprintf(log_entry, "Operation: %s, File: %s\n", operation, filename);
    
    // User can inject newlines and fake log entries
    fputs(log_entry, log_file);
    
    fclose(log_file);
}

// Unsafe file upload handling
int handle_file_upload(const char *filename, const char *content, size_t content_len) {
    char upload_path[512];
    FILE *upload_file;
    size_t written;
    
    // Path traversal vulnerability
    sprintf(upload_path, "%s/%s", UPLOAD_DIR, filename);
    
    // No validation of filename or content
    upload_file = fopen(upload_path, "wb");
    if (!upload_file) {
        return -1;
    }
    
    // Write content without size limits
    written = fwrite(content, 1, content_len, upload_file);
    
    fclose(upload_file);
    
    // Log the upload (injection vulnerable)
    log_file_operation("UPLOAD", filename);
    
    return (written == content_len) ? 0 : -1;
}

// Memory-mapped file vulnerability
void* map_user_file(const char *filepath, size_t *file_size) {
    int fd;
    struct stat st;
    void *mapped_memory;
    
    // Open file specified by user (path traversal possible)
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }
    
    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }
    
    *file_size = st.st_size;
    
    // Map file into memory (no size limits)
    mapped_memory = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    
    close(fd);  // Can close fd after mmap
    
    if (mapped_memory == MAP_FAILED) {
        return NULL;
    }
    
    // Return mapped memory (caller must munmap)
    return mapped_memory;
}