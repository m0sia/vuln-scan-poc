/*
 * pycparser compatibility header
 * Defines macros and built-ins that pycparser doesn't understand
 * Includes OpenSSL-specific compatibility for cryptographic code analysis
 */

#ifndef PYCPARSER_COMPAT_H
#define PYCPARSER_COMPAT_H

/* ========== Standard C Compatibility ========== */

/* GCC/Clang extension keywords */
#define __extension__
#define __attribute__(x)
#define __asm__(x)
#define __inline__ inline
#define __inline inline
#define __restrict__ restrict
#define __restrict restrict
#define __volatile__ volatile
#define __const const
#define __signed__ signed
#define __unsigned__ unsigned

/* Microsoft extensions */
#define __declspec(x)
#define __cdecl
#define __stdcall
#define __fastcall

/* Built-in functions */
#define __builtin_va_list int
#define __builtin_offsetof(t, m) ((size_t) &((t *)0)->m)
#define __builtin_types_compatible_p(a, b) 0
#define __builtin_constant_p(x) 0
#define __builtin_expect(x, expected_value) (x)
#define __builtin_unreachable() do { } while (0)
#define __builtin_trap() abort()

/* Assembly and compiler intrinsics */
#define asm(...)
#define __asm(...)

/* Type annotations */
#define _Nullable
#define _Nonnull
#define _Null_unspecified

/* Thread-local storage */
#define __thread
#define _Thread_local

/* Typeof keyword */
#define typeof(x) int
#define __typeof(x) int
#define __typeof__(x) int

/* Alignment */
#define __aligned(x)
#define _Alignas(x)
#define _Alignof(x) sizeof(x)

/* Static assertions */
#define _Static_assert(cond, msg)

/* ========== Generic Library Compatibility ========== */

/* Generic function pointer callback type */
typedef int (*generic_callback)(void);
typedef void (*generic_void_callback)(void);

/* ========== System Headers Compatibility ========== */

/* sys/types.h */
typedef unsigned long size_t;
typedef long ssize_t;
typedef long off_t;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned short mode_t;

/* sys/stat.h */
struct stat {
    mode_t st_mode;
    off_t st_size;
    long st_mtime;
    long st_atime;
    long st_ctime;
};

/* sys/resource.h */
struct rusage {
    long ru_maxrss;
    long ru_utime_sec;
    long ru_stime_sec;
};

#define RUSAGE_SELF 0
#define RUSAGE_CHILDREN -1

/* fcntl.h */
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR   0x0002
#define O_CREAT  0x0040
#define O_TRUNC  0x0200

/* unistd.h */
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

/* Standard library functions */
int open(const char *pathname, int flags);
int close(int fd);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
off_t lseek(int fd, off_t offset, int whence);
int fstat(int fd, struct stat *statbuf);
int ftruncate(int fd, off_t length);
int getrusage(int who, struct rusage *usage);
int mkstemp(char *template);

/* stdio.h additions - simplified for pycparser */
int printf(const char *format);
int fprintf(FILE *stream, const char *format);
int sprintf(char *str, const char *format);
FILE *fopen(const char *pathname, const char *mode);
int fclose(FILE *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

/* stdlib.h additions */
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void free(void *ptr);
void exit(int status);
void abort(void);

/* string.h additions */
char *strcpy(char *dest, const char *src);
char *strcat(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
char *strncat(char *dest, const char *src, size_t n);
size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);
void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);

#endif /* PYCPARSER_COMPAT_H */