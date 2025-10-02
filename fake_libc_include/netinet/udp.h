#ifndef _NETINET_UDP_H_
#define _NETINET_UDP_H_

#include <stdint.h>
#include <sys/types.h>

/*
 * UDP header structure
 */
struct udphdr {
    uint16_t uh_sport;  /* source port */
    uint16_t uh_dport;  /* destination port */
    uint16_t uh_ulen;   /* udp length */
    uint16_t uh_sum;    /* udp checksum */
};

/*
 * Alternative UDP header structure (Linux style)
 */
struct udp {
    uint16_t source;    /* source port */
    uint16_t dest;      /* destination port */
    uint16_t len;       /* udp length */
    uint16_t check;     /* udp checksum */
};

/* UDP header length */
#define UDP_HLEN    8   /* UDP header length */

/* UDP port definitions */
#define UDP_PORT_ECHO       7
#define UDP_PORT_DISCARD    9
#define UDP_PORT_DAYTIME    13
#define UDP_PORT_CHARGEN    19
#define UDP_PORT_TIME       37
#define UDP_PORT_NAMESERVER 42
#define UDP_PORT_WHOIS      43
#define UDP_PORT_TFTP       69
#define UDP_PORT_FINGER     79
#define UDP_PORT_HTTP       80
#define UDP_PORT_SUNRPC     111
#define UDP_PORT_NTP        123
#define UDP_PORT_NETBIOS_NS 137
#define UDP_PORT_NETBIOS_DGM 138
#define UDP_PORT_SNMP       161
#define UDP_PORT_SNMPTRAP   162
#define UDP_PORT_BGP        179
#define UDP_PORT_LDAP       389
#define UDP_PORT_HTTPS      443
#define UDP_PORT_DHCPS      67
#define UDP_PORT_DHCPC      68
#define UDP_PORT_BOOTPS     67
#define UDP_PORT_BOOTPC     68
#define UDP_PORT_DNS        53
#define UDP_PORT_SYSLOG     514
#define UDP_PORT_TALK       517
#define UDP_PORT_NTALK      518
#define UDP_PORT_RIP        520
#define UDP_PORT_TIMED      525
#define UDP_PORT_BIFF       512
#define UDP_PORT_WHO        513
#define UDP_PORT_SYSLOG     514

/* Maximum UDP packet size */
#define UDP_MAXLEN  65535   /* maximum UDP packet length */

/* UDP pseudo header for checksum calculation */
struct udp_pseudohdr {
    uint32_t src_addr;      /* source address */
    uint32_t dst_addr;      /* destination address */
    uint8_t  zero;          /* zero padding */
    uint8_t  protocol;      /* protocol (IPPROTO_UDP) */
    uint16_t length;        /* UDP length */
};

#endif /* _NETINET_UDP_H_ */