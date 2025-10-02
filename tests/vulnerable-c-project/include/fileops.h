#ifndef FILEOPS_H
#define FILEOPS_H

#include <sys/mman.h>
#include <stddef.h>

// Function declarations
int read_user_file(const char *filename);
char* create_temp_file(const char *prefix);
void list_directory_contents(const char *user_path);
int copy_file(const char *src, const char *dst);
int write_to_protected_file(const char *filename, const char *data);
int extract_archive(const char *archive_path, const char *extract_to);
void log_file_operation(const char *operation, const char *filename);
int handle_file_upload(const char *filename, const char *content, size_t content_len);
void* map_user_file(const char *filepath, size_t *file_size);

#endif // FILEOPS_H