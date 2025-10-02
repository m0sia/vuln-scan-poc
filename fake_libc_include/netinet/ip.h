#ifndef _NETINET_IP_H_
#define _NETINET_IP_H_

#include <stdint.h>
#include <sys/types.h>

/*
 * IP header structure
 */
struct iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;      /* header length */
    uint8_t version:4;  /* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;  /* version */
    uint8_t ihl:4;      /* header length */
#else
# error "Please fix <bits/endian.h>"
#endif
    uint8_t tos;        /* type of service */
    uint16_t tot_len;   /* total length */
    uint16_t id;        /* identification */
    uint16_t frag_off;  /* fragment offset field */
    uint8_t ttl;        /* time to live */
    uint8_t protocol;   /* protocol */
    uint16_t check;     /* checksum */
    uint32_t saddr;     /* source address */
    uint32_t daddr;     /* dest address */
    /*The options start here. */
};

/*
 * BSD-style IP header
 */
struct ip {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ip_hl:4;        /* header length */
    uint8_t ip_v:4;         /* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip_v:4;         /* version */
    uint8_t ip_hl:4;        /* header length */
#else
# error "Please fix <bits/endian.h>"
#endif
    uint8_t ip_tos;         /* type of service */
    uint16_t ip_len;        /* total length */
    uint16_t ip_id;         /* identification */
    uint16_t ip_off;        /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    uint8_t ip_ttl;         /* time to live */
    uint8_t ip_p;           /* protocol */
    uint16_t ip_sum;        /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};

/*
 * Time stamp option structure.
 */
struct ip_timestamp {
    uint8_t ipt_code;       /* IPOPT_TS */
    uint8_t ipt_len;        /* size of structure (variable) */
    uint8_t ipt_ptr;        /* index of current entry */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ipt_flg:4;      /* flags, see below */
    uint8_t ipt_oflw:4;     /* overflow counter */
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ipt_oflw:4;     /* overflow counter */
    uint8_t ipt_flg:4;      /* flags, see below */
#else
# error "Please fix <bits/endian.h>"
#endif
    uint32_t data[9];
};

/* IP protocol numbers */
#define IPPROTO_IP      0   /* dummy for IP */
#define IPPROTO_ICMP    1   /* control message protocol */
#define IPPROTO_IGMP    2   /* group mgmt protocol */
#define IPPROTO_GGP     3   /* gateway^2 (deprecated) */
#define IPPROTO_TCP     6   /* tcp */
#define IPPROTO_PUP     12  /* pup */
#define IPPROTO_UDP     17  /* user datagram protocol */
#define IPPROTO_IDP     22  /* xns idp */
#define IPPROTO_RAW     255 /* raw IP packet */

/* IP options */
#define IPOPT_COPIED(o)     ((o)&0x80)
#define IPOPT_CLASS(o)      ((o)&0x60)
#define IPOPT_NUMBER(o)     ((o)&0x1f)

#define IPOPT_CONTROL       0x00
#define IPOPT_RESERVED1     0x20
#define IPOPT_DEBMEAS       0x40
#define IPOPT_RESERVED2     0x60

#define IPOPT_EOL           0       /* end of option list */
#define IPOPT_NOP           1       /* no operation */

#define IPOPT_RR            7       /* record packet route */
#define IPOPT_TS            68      /* timestamp */
#define IPOPT_SECURITY      130     /* provide s,c,h,tcc */
#define IPOPT_LSRR          131     /* loose source route */
#define IPOPT_SSRR          137     /* strict source route */
#define IPOPT_RA            148     /* router alert */

/* IP version */
#define IPVERSION   4       /* IP version number */
#define IP_MAXPACKET    65535   /* maximum packet size */

/* IP header minimum length */
#define IP_HLEN     20      /* minimum IP header length */

/* IP TOS field */
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_MINCOST       0x02

/* IP precedence */
#define IPTOS_PREC_NETCONTROL       0xe0
#define IPTOS_PREC_INTERNETCONTROL  0xc0
#define IPTOS_PREC_CRITIC_ECP       0xa0
#define IPTOS_PREC_FLASHOVERRIDE    0x80
#define IPTOS_PREC_FLASH            0x60
#define IPTOS_PREC_IMMEDIATE        0x40
#define IPTOS_PREC_PRIORITY         0x20
#define IPTOS_PREC_ROUTINE          0x00

#endif /* _NETINET_IP_H_ */