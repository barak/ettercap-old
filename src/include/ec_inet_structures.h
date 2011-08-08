
#if !defined(EC_INET_STRUCTURES_H)
#define EC_INET_STRUCTURES_H

#ifdef CYGWIN
   #include <windows.h>
   #include <winsock2.h>
   #include "../missing/inet_aton.h"
#else
   #include <sys/socket.h>
#endif

#ifndef HAVE_SOCKLEN_T
   typedef unsigned int socklen_t;
#endif

#ifdef LINUX
   #include <features.h>         /* for the glibc version number */

   #if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
      #include <netpacket/packet.h>
      #include <net/ethernet.h>     /* the L2 protocols */
   #else
      #include <asm/types.h>
      #include <linux/if_packet.h>
      #include <linux/if_ether.h>   /* The L2 protocols */
      #ifdef HAVE_NET_ETHERNET_H
         #include <net/ethernet.h>
      #endif
   #endif
#endif

#if !defined(OPENBSD) && !defined(CYGWIN)
   #include <net/if_arp.h>
#endif

#ifdef CYGWIN
   #include "../missing/include/if_arp.h"
#endif


#include <sys/types.h>
#include <netinet/in_systm.h>

#ifdef CYGWIN
   #include <netinet/tcp.h>
   #include <netinet/ip.h>
   #include "../missing/include/ip_icmp.h"
#else
   #include <net/if.h>
   #include <netdb.h>
   #include <netinet/tcp.h>
   #include <netinet/in.h>
   #include <netinet/ip.h>
   #include <netinet/ip_icmp.h>
   #include <arpa/inet.h>
#endif



typedef struct {
   char dest_mac[6];          // dest ethernet address
   char source_mac[6];        // source ethernet address
   u_short type;              // type of packet
} ETH_header;


typedef struct {
   u_short hw_type;           // hardware type
   u_short proto_type;        // protocol type
   char ha_len;               // hardware address len
   char pa_len;               // protocol address len
   u_short opcode;            // arp opcode
   char source_add[6];        // source mac
   char source_ip[4];         // source ip
   char dest_add[6];          // dest mac
   char dest_ip[4];           // dest ip
} ARP_header;


typedef struct {
#ifdef WORDS_BIGENDIAN
   u_char version:4;          // ip version
   u_char h_len:4;            // header len
#else
   u_char h_len:4;            // header len
   u_char version:4;          // ip version
#endif
   u_char tos;                // type of service
   u_short t_len;             // total len
   u_short ident;             // ip ident
   u_short frag_and_flags;    // fragments and flags
   u_char  ttl;               // time to live
   u_char proto;              // transport protocol
   u_short checksum;          // IP checksum
   u_long source_ip;          // source ip
   u_long dest_ip;            // destination ip
} IP_header;


typedef struct {
   u_char type;               // icmp type
   u_char code;               // type sub code
   u_short checksum;          // ones complement checksum of struct
   union
   {
       struct
       {
           u_short id;        // ident
           u_short seq;       // sequence number
       } echo;
       u_long gateway;        // gateway address
       struct
       {
           u_short unused;
           u_short mtu;
       } frag;                // path mtu discovery
    } un;
} ICMP_header;


typedef struct
{
   u_short source;            // source port
   u_short dest;              // destination port
   u_long seq;                // sequence number
   u_long ack_seq;            // acknowledgement number
#ifdef WORDS_BIGENDIAN
   u_char doff:4;             // data offset
   u_char unused:4;           // unused
#else
   u_char unused:4;           // unused
   u_char doff:4;             // data offset
#endif
   u_char  flags;             // tcp flags
   u_short window;            // window
   u_short checksum;          // checksum
   u_short urg_ptr;           // urgent pointer
} TCP_header;


typedef struct
{
   u_short source;             // source port
   u_short dest;               // destination port
   u_short len;                // packet length
   u_short checksum;           // checksum
} UDP_header;


#define MAX_PACKET_SIZE      0xffff

#define ETH_HEADER           0xe     // Etherner header:     14 bytes
#define ARP_HEADER           0x1c    // ARP header:          28 bytes

#define IP_HEADER            0x14    // IP header:           20 bytes

#define ICMP_HEADER          0x8     // ICMP header:          8 bytes

#define TCP_HEADER           0x14    // TCP header:          20 bytes
#define UDP_HEADER           0x8     // UDP header:           8 bytes

#define TH_FIN  0x01    // TCP Flags
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20

#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WSCALE           3
#define TCPOPT_SACKOK           4
#define TCPOPT_TIMESTAMP        8


#ifndef IP_DF
#define IP_DF 0x4000
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

#ifndef SOL_PACKET      // glibc 2.1 bug
#define SOL_PACKET 263
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef MSG_TRUNC
#define MSG_TRUNC 0x20
#endif

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#ifndef PACKET_HOST
#define PACKET_HOST 0
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif

#ifndef ICMP_SOURCE_QUENCH
#define ICMP_SOURCE_QUENCH 4
#endif


#ifdef WORDS_BIGENDIAN
   #define ptohs(x) ( (u_short)                       \
                      ((u_short)*((u_char *)x+1)<<8|  \
                      (u_short)*((u_char *)x+0)<<0)   \
                    )

   #define ptohl(x) ( (u_long)*((u_char *)x+3)<<24|  \
                      (u_long)*((u_char *)x+2)<<16|  \
                      (u_long)*((u_char *)x+1)<<8|   \
                      (u_long)*((u_char *)x+0)<<0    \
                    )
#else
   #define ptohs(x) *(u_short *)(x)
   #define ptohl(x) *(u_long *)(x)
#endif

#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))


#endif // EC_INET_STRUCTURES_H

/* EOF */
