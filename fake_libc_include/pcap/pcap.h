#ifndef _PCAP_PCAP_H_
#define _PCAP_PCAP_H_

#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>

/* Forward declarations */
typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;

/* Data link types */
#define DLT_NULL        0       /* BSD loopback encapsulation */
#define DLT_EN10MB      1       /* Ethernet (10Mb) */
#define DLT_EN3MB       2       /* Experimental Ethernet (3Mb) */
#define DLT_AX25        3       /* Amateur Radio AX.25 */
#define DLT_PRONET      4       /* Proteon ProNET Token Ring */
#define DLT_CHAOS       5       /* Chaos */
#define DLT_IEEE802     6       /* 802.5 Token Ring */
#define DLT_ARCNET      7       /* ARCNET, with BSD-style header */
#define DLT_SLIP        8       /* Serial Line IP */
#define DLT_PPP         9       /* Point-to-point Protocol */
#define DLT_FDDI        10      /* FDDI */
#define DLT_RAW         12      /* Raw IP */
#define DLT_LINUX_SLL   113     /* Linux cooked sockets */
#define DLT_IEEE802_11  105     /* IEEE 802.11 wireless */

/* Error codes */
#define PCAP_ERROR                      -1      /* generic error code */
#define PCAP_ERROR_BREAK                -2      /* loop terminated by pcap_breakloop */
#define PCAP_ERROR_NOT_ACTIVATED        -3      /* the capture needs to be activated */
#define PCAP_ERROR_ACTIVATED            -4      /* the operation can't be performed on already activated captures */
#define PCAP_ERROR_NO_SUCH_DEVICE       -5      /* no such device exists */
#define PCAP_ERROR_RFMON_NOTSUP         -6      /* this device doesn't support rfmon (monitor) mode */
#define PCAP_ERROR_NOT_RFMON            -7      /* operation supported only in monitor mode */
#define PCAP_ERROR_PERM_DENIED          -8      /* no permission to open the device */
#define PCAP_ERROR_IFACE_NOT_UP         -9      /* interface isn't up */
#define PCAP_ERROR_CANTSET_TSTAMP_TYPE  -10     /* this device doesn't support setting the time stamp type */
#define PCAP_ERROR_PROMISC_PERM_DENIED  -11     /* you don't have permission to capture in promiscuous mode */

/* Direction values */
#define PCAP_D_INOUT    0
#define PCAP_D_IN       1
#define PCAP_D_OUT      2

/* Packet header structure */
struct pcap_pkthdr {
    struct timeval ts;      /* time stamp */
    uint32_t caplen;        /* length of portion present */
    uint32_t len;           /* length this packet (off wire) */
};

/* Statistics structure */
struct pcap_stat {
    unsigned int ps_recv;       /* number of packets received */
    unsigned int ps_drop;       /* number of packets dropped */
    unsigned int ps_ifdrop;     /* drops by interface XXX not yet supported */
};

/* Interface description */
struct pcap_if {
    struct pcap_if *next;
    char *name;                 /* name to hand to "pcap_open_live()" */
    char *description;          /* textual description of interface, or NULL */
    struct pcap_addr *addresses;
    uint32_t flags;             /* PCAP_IF_ interface flags */
};

/* Interface address */
struct pcap_addr {
    struct pcap_addr *next;
    struct sockaddr *addr;      /* address */
    struct sockaddr *netmask;   /* netmask for that address */
    struct sockaddr *broadaddr; /* broadcast address for that address */
    struct sockaddr *dstaddr;   /* P2P destination address for that address */
};

/* Interface flags */
#define PCAP_IF_LOOPBACK        0x00000001      /* interface is loopback */
#define PCAP_IF_UP              0x00000002      /* interface is up */
#define PCAP_IF_RUNNING         0x00000004      /* interface is running */

/* Function prototypes */
char *pcap_lookupdev(char *errbuf);
int pcap_lookupnet(const char *device, uint32_t *netp, uint32_t *maskp, char *errbuf);
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
pcap_t *pcap_open_dead(int linktype, int snaplen);
void pcap_close(pcap_t *p);
int pcap_loop(pcap_t *p, int cnt, void (*callback)(unsigned char *, const struct pcap_pkthdr *, const unsigned char *), unsigned char *user);
int pcap_dispatch(pcap_t *p, int cnt, void (*callback)(unsigned char *, const struct pcap_pkthdr *, const unsigned char *), unsigned char *user);
const unsigned char *pcap_next(pcap_t *p, struct pcap_pkthdr *h);
int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const unsigned char **pkt_data);
void pcap_breakloop(pcap_t *p);
int pcap_stats(pcap_t *p, struct pcap_stat *ps);
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
int pcap_setdirection(pcap_t *p, int d);
int pcap_getnonblock(pcap_t *p, char *errbuf);
int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf);
int pcap_inject(pcap_t *p, const void *buf, size_t size);
int pcap_sendpacket(pcap_t *p, const unsigned char *buf, int size);
const char *pcap_statustostr(int error);
const char *pcap_strerror(int error);
char *pcap_geterr(pcap_t *p);
void pcap_perror(pcap_t *p, const char *prefix);
int pcap_compile(pcap_t *p, struct bpf_program *program, const char *buf, int optimize, uint32_t netmask);
int pcap_compile_nopcap(int snaplen_arg, int linktype_arg, struct bpf_program *program, const char *buf, int optimize, uint32_t netmask);
void pcap_freecode(struct bpf_program *fp);
int pcap_datalink(pcap_t *p);
int pcap_list_datalinks(pcap_t *p, int **dlt_buf);
int pcap_set_datalink(pcap_t *p, int dlt);
void pcap_free_datalinks(int *dlt_list);
int pcap_datalink_name_to_val(const char *name);
const char *pcap_datalink_val_to_name(int dlt);
const char *pcap_datalink_val_to_description(int dlt);
int pcap_snapshot(pcap_t *p);
int pcap_is_swapped(pcap_t *p);
int pcap_major_version(pcap_t *p);
int pcap_minor_version(pcap_t *p);
int pcap_fileno(pcap_t *p);

/* Dumper functions */
pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname);
void pcap_dump_close(pcap_dumper_t *p);
void pcap_dump(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *sp);
FILE *pcap_dump_file(pcap_dumper_t *p);
long pcap_dump_ftell(pcap_dumper_t *p);
int pcap_dump_flush(pcap_dumper_t *p);

/* Interface enumeration */
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
void pcap_freealldevs(pcap_if_t *alldevs);

/* Library version */
const char *pcap_lib_version(void);

/* BPF program structure (minimal) */
struct bpf_program {
    unsigned int bf_len;
    struct bpf_insn *bf_insns;
};

struct bpf_insn {
    unsigned short code;
    unsigned char jt;
    unsigned char jf;
    uint32_t k;
};

#endif /* _PCAP_PCAP_H_ */