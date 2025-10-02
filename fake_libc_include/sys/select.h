#ifndef _SYS_SELECT_H_
#define _SYS_SELECT_H_

#include "_fake_defines.h"
#include "_fake_typedefs.h"
#include <sys/time.h>

/* Maximum number of file descriptors in `fd_set'.  */
#define FD_SETSIZE 1024

/* fd_set structure */
typedef struct {
    long fds_bits[FD_SETSIZE / (8 * sizeof(long))];
} fd_set;

/* Access macros for `fd_set'.  */
#define FD_SET(fd, fdsetp)      ((fdsetp)->fds_bits[(fd) / (8 * sizeof(long))] |= (1UL << ((fd) % (8 * sizeof(long)))))
#define FD_CLR(fd, fdsetp)      ((fdsetp)->fds_bits[(fd) / (8 * sizeof(long))] &= ~(1UL << ((fd) % (8 * sizeof(long)))))
#define FD_ISSET(fd, fdsetp)    (((fdsetp)->fds_bits[(fd) / (8 * sizeof(long))] & (1UL << ((fd) % (8 * sizeof(long))))) != 0)
#define FD_ZERO(fdsetp)         do { \
    int __i; \
    for (__i = 0; __i < (int)(FD_SETSIZE / (8 * sizeof(long))); __i++) \
        (fdsetp)->fds_bits[__i] = 0; \
} while (0)

/* Function prototypes */
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);

#endif /* _SYS_SELECT_H_ */
