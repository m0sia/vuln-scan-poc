#ifndef _SYS_PARAM_H_
#define _SYS_PARAM_H_

#include "_fake_defines.h"
#include "_fake_typedefs.h"

/* System parameters and limits */
#define MAXPATHLEN      1024    /* Maximum length of a pathname */
#define MAXHOSTNAMELEN  256     /* Maximum length of hostname */
#define MAXNAMLEN       255     /* Maximum length of a file name */

/* Page size macros */
#define PAGESIZE        4096    /* Machine page size */
#define PAGE_SIZE       PAGESIZE
#define NBPG            PAGESIZE

/* Process limits */
#define MAXUID          65535   /* Maximum user ID */
#define MAXGID          65535   /* Maximum group ID */
#define NOGROUP         (-1)    /* Marker for empty group set member */

/* File system parameters */
#define NOFILE          256     /* Default max open files per process */
#define MAXSYMLINKS     32      /* Maximum symbolic links in pathname resolution */

/* Bit map related macros */
#define NBBY            8       /* Number of bits in a byte */

/* Priority-related definitions */
#define PSWP            0
#define PVM             4
#define PINOD           8
#define PRIBIO          16
#define PRIUBA          20
#define PZERO           22
#define PPIPE           26
#define PWAIT           30
#define PLOCK           36
#define PSLEP           40
#define PUSER           50

/* MIN/MAX macros */
#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

/* Round macros */
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))  /* to any y */
#define rounddown(x, y) (((x)/(y))*(y))

/* Macros for number of elements */
#define MAXBSIZE        65536   /* must be power of 2 */
#define MAXFRAG         8

/* BSD compatibility */
#define MAXCOMLEN       16      /* max command name remembered */
#define MAXINTERP       64      /* max interpreter file name length */
#define MAXLOGNAME      17      /* max login name length (incl. NUL) */

/* Time constants */
#define SECSPERHOUR     (60*60)
#define SECSPERDAY      (24*SECSPERHOUR)

/* BSD howmany macro */
#define howmany(x, y)   (((x)+((y)-1))/(y))

/* Machine-dependent parameters */
#define ALIGNBYTES      (sizeof(long) - 1)
#define ALIGN(p)        (((unsigned long)(p) + ALIGNBYTES) & ~ALIGNBYTES)

#endif /* _SYS_PARAM_H_ */