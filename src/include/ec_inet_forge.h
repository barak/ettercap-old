
#if !defined(EC_INET_FORGE_H)
#define EC_INET_FORGE_H


#include <sys/types.h>

extern u_char * Inet_Forge_packet( u_short size ); // size of the allocated mem

extern int Inet_Forge_packet_destroy( u_char *buf );

extern int Inet_Forge_ethernet( u_char *buf,
                                u_char *source,    // source mac address
                                u_char *dest,      // dest mac address
                                u_short type );    // protocol type

extern int Inet_Forge_arp( u_char *buf,
                           u_short op,             // arp opcode
                           u_char *sa,             // source mac address
                           u_long sip,             // sourde ip address
                           u_char *da,             // dest mac address
                           u_long dip );           // dest ip address

extern int Inet_Forge_ip( u_char *buf,
                          u_long src,              // source ip
                          u_long dst,              // dest ip
                          u_short len,             // len of the payload
                          u_short ident,           // ident
                          u_short f_f,             // fragments and flags
                          u_char proto );          // transport protocol

extern int Inet_Forge_icmp( u_char *buf,
                            u_char type,           // icmp type
                            u_char code,           // icmp code
                            u_char *data,          // data
                            int data_len );        // data length

extern int Inet_Forge_tcp( u_char *buf,
                           u_short sp,             // source port
                           u_short dp,             // dest port
                           u_long seq,             // sequence number
                           u_long ack,             // acknowledgement number
                           u_char flags,           // tcp flags
                           u_char *data,           // payload
                           int data_len );         // payload len

extern int Inet_Forge_udp( u_char *buf,
                           u_short sp,             // source port
                           u_short dp,             // dest port
                           u_char *data,           // payload
                           int data_len );         // payload len

extern int Inet_Forge_Insert_TCPOpt( u_char *buf,
                                     u_char *options, // raw options buffer
                                     int optlen );    // options length

extern u_short Inet_Forge_ChecksumIP( u_short *buffer,
                                      int size);         // size of ip header

extern u_short Inet_Forge_Checksum( u_short *buffer,
                                    u_short proto,    // protocol type (TCP or UDP)
                                    u_short size,     // size of tcp packet (header + payload)
                                    u_long IPsource,  // ip source (for pseudoheader)
                                    u_long IPdest);   // ip dest (for pseudoheader)

extern u_long Inet_Forge_CRC(u_char *buffer, // the buffer
                             int len);       // buffer lenght

#endif

/* EOF */
