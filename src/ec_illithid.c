/*
    ettercap -- illithid -- the sniffer module

    Copyright (C) 2001  ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Id: ec_illithid.c,v 1.17 2002/02/11 00:58:17 alor Exp $
*/

#include "include/ec_main.h"

#include <fcntl.h>
#include <signal.h>

#include "include/ec_inet.h"
#include "include/ec_inet_forge.h"
#include "include/ec_inet_structures.h"
#include "include/ec_buffer.h"
#include "include/ec_error.h"
#include "include/ec_dissector.h"
#include "include/ec_filterdrop.h"
#include "include/ec_parser.h"
#include "include/ec_thread.h"
#include "include/ec_decodedata.h"
#include "include/ec_plugins.h"

#define HASHES 256
#define PCK_STOD 1
#define PCK_DTOS 2
#define PCK_ANY  3
#define PCK_DROP 0

#define MOD_LOG      3
#define MOD_DROP     2
#define MOD_REPLACED 1
#define MOD_ORIG     0

typedef struct {
    unsigned int IP;
    unsigned short Port;
    unsigned int Seq;
    unsigned int Ack;
    unsigned int ByteSent;
    unsigned int PacketSent;
    unsigned short IPID;
    unsigned short datalen;
    unsigned char MAC[6];
    unsigned char flags;
} side_elem;

typedef struct {
    side_elem elem1;
    side_elem elem2;
    char proto;
    struct Ielem *next;
} Ielem;


typedef struct {
    short mode;
    char iface[10];
    char IP1p[16];
    char IP2p[16];
    char MAC1p[20];
    char MAC2p[20];
} illithid_param;


// global data
int sock, Connection_Mode=1;
unsigned char MyMAC[6];
static Ielem* hash_table[HASHES];
int illithid_gwip;
int illithid_buffer = -1;
pthread_t decoder_pid;

pthread_mutex_t decoder_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t decoder_cond = PTHREAD_COND_INITIALIZER;

// protos...

pthread_t Illithid_ARPBased_GetConnections(char *iface, char *IP1p, char *IP2p, char *MAC1, char *MAC2);
pthread_t Illithid_PublicARP_GetConnections(char *iface, char *IP1p, char *IP2p, char *MAC1, char *MAC2);
pthread_t Illithid_IPBased_GetConnections(char *iface, char *IP1p, char *IP2p);
pthread_t Illithid_MACBased_GetConnections(char *iface, char *MAC1p, char *MAC2p);

int Illithid_ToBeSniffed(SNIFFED_DATA *data);
int Illithid_ToBeSniffed_ip(u_long source, u_long dest, CONNECTION *data);
int Illithid_ToBeSniffed_mac(char *source, char *dest, CONNECTION *data);

void * Illithid_GetConnections(void *);
void Illithid_Reset_Conn(void *);
Ielem **Illithid_Find_Session(unsigned int IP1, unsigned int IP2, unsigned short Port1, unsigned short Port2, char proto, Ielem *outs);
void Illithid_Set_Session(Ielem **session, Ielem *outs, short mode);
void * Illithid_Decoder(void *dummy);
void Illithid_Decoder_Put(CONNECTION *data);

//---------------------------

void * Illithid_Decoder(void *dummy)      // decoder thread
{
   CONNECTION data_to_ettercap;
   Buffer_Flush(illithid_buffer);
   loop
   {
      pthread_testcancel();

      if (Buffer_Get(illithid_buffer, &data_to_ettercap, sizeof(CONNECTION)) > 0)
         Decodedata_MakeConnectionList(&data_to_ettercap);
      else
      {
         pthread_cond_wait(&decoder_cond, &decoder_mtx);
      }
   }
}


void Illithid_Decoder_Put(CONNECTION *data)
{
   Buffer_Put(illithid_buffer, data, sizeof(CONNECTION));
   pthread_cond_signal(&decoder_cond);
}


pthread_t Illithid_ARPBased_GetConnections(char *iface, char *IP1p, char *IP2p, char *MAC1p, char *MAC2p)
{
   static illithid_param param;

#ifdef DEBUG
   Debug_msg("Illithid_ARPBased_GetConnections -- [%s] [%s] [%s] [%s]", IP1p, IP2p, MAC1p, MAC2p);
#endif

   param.mode = ARPBASED;
   strlcpy(param.iface, iface, sizeof(param.iface));
   strlcpy(param.IP1p, IP1p, sizeof(param.IP1p));
   strlcpy(param.IP2p, IP2p, sizeof(param.IP2p));
   strlcpy(param.MAC1p, MAC1p, sizeof(param.MAC1p));
   strlcpy(param.MAC2p, MAC2p, sizeof(param.MAC2p));

   return ECThread_create("illithid", &Illithid_GetConnections, &param);
}

pthread_t Illithid_PublicARP_GetConnections(char *iface, char *IP1p, char *IP2p, char *MAC1p, char *MAC2p)
{
   static illithid_param param;

#ifdef DEBUG
   Debug_msg("Illithid_PublicARP_GetConnections -- [%s] [%s] [%s] [%s]", IP1p, IP2p, MAC1p, MAC2p);
#endif

   param.mode = PUBLICARP;
   strlcpy(param.iface, iface, sizeof(param.iface));
   strlcpy(param.IP1p, IP1p, sizeof(param.IP1p));
   strlcpy(param.IP2p, IP2p, sizeof(param.IP2p));
   strlcpy(param.MAC1p, MAC1p, sizeof(param.MAC1p));
   strlcpy(param.MAC2p, MAC2p, sizeof(param.MAC2p));

   return ECThread_create("illithid", &Illithid_GetConnections, &param);
}



pthread_t Illithid_IPBased_GetConnections(char *iface, char *IP1p, char *IP2p)
{
   static illithid_param param;

#ifdef DEBUG
   Debug_msg("Illithid_IPBased_GetConnections -- [%s] [%s]", IP1p, IP2p);
#endif

   param.mode = IPBASED;
   strlcpy(param.iface, iface, sizeof(param.iface));
   strlcpy(param.IP1p, IP1p, sizeof(param.IP1p));
   strlcpy(param.IP2p, IP2p, sizeof(param.IP2p));
   strcpy(param.MAC1p, "");
   strcpy(param.MAC2p, "");

   return ECThread_create("illithid", &Illithid_GetConnections, &param);

}


pthread_t Illithid_MACBased_GetConnections(char *iface, char *MAC1p, char *MAC2p)
{
   static illithid_param param;

#ifdef DEBUG
   Debug_msg("Illithid_MACBased_GetConnections -- [%s] [%s]", MAC1p, MAC2p);
#endif

   param.mode = MACBASED;
   strlcpy(param.iface, iface, sizeof(param.iface));
   strcpy(param.IP1p, "");
   strcpy(param.IP2p, "");
   strlcpy(param.MAC1p, MAC1p, sizeof(param.MAC1p));
   strlcpy(param.MAC2p, MAC2p, sizeof(param.MAC2p));

   return ECThread_create("illithid", &Illithid_GetConnections, &param);
}


void * Illithid_GetConnections(void *param)
{
   int len, MTU, delta=0, datalen, nchars, IP1=0, IP2=0;
   short pkttype, forward_mode;
   struct in_addr addr;
   ETH_header *eth;
   IP_header *ip;
   TCP_header *tcp;
   UDP_header *udp;
   CONNECTION data_to_ettercap;
   SNIFFED_DATA sniff_data_to_ettercap;
   u_char *buffer;
   u_long IP_Test=0, MyIP, NetMask;
   int Act_Connection_Mode = Connection_Mode;
   unsigned char *data;
   char *ins_pck;
   unsigned char MAC1[6];
   unsigned char MAC2[6];
   unsigned char GWMAC[6];

   exit_func(Illithid_Reset_Conn);

#ifdef CYGWIN
   if (illithid_buffer == -1) illithid_buffer = Buffer_Create(5.0e5);   // 500 Kb
#else
   if (illithid_buffer == -1) illithid_buffer = Buffer_Create(5.0e4);   // 50 Kb
#endif
   decoder_pid = ECThread_create("decoder", &Illithid_Decoder, NULL);

   if (inet_aton(((illithid_param *)param)->IP1p,&addr))
       IP1 = addr.s_addr;
   if (inet_aton(((illithid_param *)param)->IP2p,&addr))
       IP2 = addr.s_addr;

   Inet_GetMACfromString(((illithid_param *)param)->MAC1p, MAC1);
   Inet_GetMACfromString(((illithid_param *)param)->MAC2p, MAC2);

   if (illithid_gwip) memcpy(GWMAC, Inet_MacFromIP(illithid_gwip), 6);  // get the gateway's mac for smart arp on a client

   sock = Inet_OpenRawSock(((illithid_param *)param)->iface);
   Inet_GetIfaceInfo( ((illithid_param *)param)->iface, &MTU, MyMAC, &MyIP, &NetMask);

   fcntl(sock,F_SETFL,O_NONBLOCK);
   fcntl(pipe_inject[0], F_SETFL, O_NONBLOCK);
   fcntl(pipe_kill[0], F_SETFL, O_NONBLOCK);

   forward_mode = ((illithid_param *)param)->mode;
   if (((illithid_param *)param)->mode == ARPBASED && ( IP1 == 0 || IP2 == 0 ) )
       forward_mode = PUBLICARP;

   if (((illithid_param *)param)->mode > PUBLICARP)
      Inet_SetPromisc(((illithid_param *)param)->iface);
   else
      IP_Test=MyIP&NetMask;

   buffer = Inet_Forge_packet(MTU*2);
   ins_pck = Inet_Forge_packet(MTU);

   loop
   {
      pthread_testcancel();
      delta = 0;
      memset(buffer, 0, MTU);    // REQUIRED BY DISSECTORS !!!

      len = Inet_GetRawPacket(sock, buffer, MTU, &pkttype);

#ifdef PERMIT_PLUGINS
      if (len > 0) {
         RAW_PACKET praw;

         praw.buffer = buffer;
         praw.len = &len;     // the plugin can modify the len of the packet

         Plugin_HookPoint(PCK_RECEIVED_RAW, &praw);     // HOOK POINT: PCK_RECEIVED_RAW
      }
#endif

      if (len > 0 && ( ((illithid_param *)param)->mode > PUBLICARP || pkttype == PACKET_HOST))
      {
         char PckDir = PCK_DROP;
         int dontforward = 0;

         memset(&data_to_ettercap, 0, sizeof(CONNECTION));
         memset(&sniff_data_to_ettercap, 0, sizeof(SNIFFED_DATA));
         Act_Connection_Mode = Connection_Mode;

         eth = (ETH_header *)buffer;

         memcpy(data_to_ettercap.source_mac,eth->source_mac,6);
         memcpy(data_to_ettercap.dest_mac,eth->dest_mac,6);

         if ( ntohs(eth->type) == ETH_P_IP )
         {
            ip = (IP_header *)(eth+1);

            data_to_ettercap.fast_source_ip = ntohl(ip->source_ip);
            data_to_ettercap.fast_dest_ip = ntohl(ip->dest_ip);
            strlcpy(data_to_ettercap.source_ip, int_ntoa(ip->source_ip), sizeof(data_to_ettercap.source_ip));
            strlcpy(data_to_ettercap.dest_ip, int_ntoa(ip->dest_ip), sizeof(data_to_ettercap.dest_ip));

            if (!Act_Connection_Mode)
            {
               sniff_data_to_ettercap.fast_source_ip = ntohl(ip->source_ip);
               sniff_data_to_ettercap.fast_dest_ip = ntohl(ip->dest_ip);
               strlcpy(sniff_data_to_ettercap.source_ip, int_ntoa(ip->source_ip), sizeof(sniff_data_to_ettercap.source_ip));
               strlcpy(sniff_data_to_ettercap.dest_ip, int_ntoa(ip->dest_ip), sizeof(sniff_data_to_ettercap.dest_ip));
            }

            if (forward_mode == MACBASED)
               PckDir = Illithid_ToBeSniffed_mac(MAC1, MAC2, &data_to_ettercap);
            else if ( forward_mode == IPBASED)
               PckDir = Illithid_ToBeSniffed_ip(ntohl(IP1), ntohl(IP2), &data_to_ettercap);
            else if ( forward_mode == ARPBASED && (ip->dest_ip==IP1 || ip->source_ip==IP2) && (((ip->dest_ip&NetMask)!=IP_Test || (ip->source_ip&NetMask)!=IP_Test)
                 || (ip->dest_ip==IP1 && ip->source_ip==IP2)))
            {
               memcpy(eth->dest_mac, MAC1, 6);
               memcpy(eth->source_mac, MyMAC, 6);
               PckDir = PCK_DTOS;
            }
            else if ( forward_mode == ARPBASED && (ip->dest_ip==IP2 || ip->source_ip==IP1) && (((ip->dest_ip&NetMask)!=IP_Test || (ip->source_ip&NetMask)!=IP_Test)
                 || (ip->dest_ip==IP2 && ip->source_ip==IP1)))
            {
               memcpy(eth->dest_mac, MAC2, 6);
               memcpy(eth->source_mac, MyMAC, 6);
               PckDir = PCK_STOD;
            }
            else if (forward_mode == PUBLICARP)
            {
               if (data_to_ettercap.fast_dest_ip == ntohl(IP1))
               {
                  memcpy(eth->dest_mac, MAC1, 6);
                  PckDir = PCK_DTOS;
               }
               else if (data_to_ettercap.fast_dest_ip == ntohl(IP2))
               {
                  memcpy(eth->dest_mac, MAC2, 6);
                  PckDir = PCK_STOD;
               }
               else if ((ip->dest_ip&NetMask)!=IP_Test)
               {
                  if ( IP1 == 0)  // 0 its ANY
                  {
                     if (memcmp(eth->source_mac, MAC2, 6))
                     {
                         memcpy(eth->dest_mac, MAC2, 6);
                         PckDir = PCK_STOD;
                     }
                     else
                     {
                        memcpy(eth->dest_mac, GWMAC, 6);
                        PckDir = PCK_DTOS;
                     }
                  }
                  else
                  {
                     if (memcmp(eth->source_mac, MAC1, 6))
                     {
                         memcpy(eth->dest_mac, MAC1, 6);
                         PckDir = PCK_DTOS;
                     }
                     else
                     {
                        memcpy(eth->dest_mac, GWMAC, 6);
                        PckDir = PCK_STOD;
                     }
                  }
               }
               else if (ip->dest_ip!=MyIP)
               {
                  int i;

                  if ( IP1 == 0 )   // 0 its ANY
                     PckDir = PCK_DTOS;
                  else
                     PckDir = PCK_STOD;

                  for(i = 1; i<number_of_hosts_in_lan; i++)
                  {
                     if (inet_addr(Host_In_LAN[i].ip) == ip->dest_ip)
                     {
                        Inet_GetMACfromString(Host_In_LAN[i].mac, eth->dest_mac);
                        break;
                     }
                  }
                  if (i>=number_of_hosts_in_lan)
                     memcpy(eth->dest_mac, Inet_MacFromIP(ip->dest_ip), 6);
               }
               memcpy(eth->source_mac, MyMAC, 6);
            }

            memcpy(data_to_ettercap.dest_mac,eth->dest_mac,6);

#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
            if ( (ip->dest_ip & htonl(0xff000000))==htonl(0x01000000)) PckDir=PCK_ANY;    // for https dissection
#endif

            if ( PckDir && ip->proto == IPPROTO_TCP)
            {
               unsigned char *tcp_data;
               int tcp_datalen;
               tcp = (TCP_header *) ((int)ip + ip->h_len * 4);

               if (!( ntohs(ip->frag_and_flags) & IP_OFFMASK))
               {
                  DISSECTION dissector_data;

                  tcp_data = (char *)((int)tcp + tcp->doff * 4);
                  tcp_datalen = (int)ip + ntohs(ip->t_len) - (int)tcp_data;

                  if (tcp_datalen < 0 || ntohs(ip->t_len) > len) goto send;

						tcp_datalen = (tcp_datalen > MAX_DATA) ? MAX_DATA : tcp_datalen;  // don't accept bogus sized packets

                  data_to_ettercap.source_port = ntohs(tcp->source);
                  data_to_ettercap.dest_port = ntohs(tcp->dest);
                  data_to_ettercap.source_seq = ntohl(tcp->seq) + tcp_datalen;
                  data_to_ettercap.dest_seq = ntohl(tcp->seq) + tcp_datalen;
                  data_to_ettercap.flags = tcp->flags;
                  data_to_ettercap.proto = 'T';
                  data_to_ettercap.datalen = tcp_datalen;

                  if (!Act_Connection_Mode)
                  {
                     sniff_data_to_ettercap.source_port = ntohs(tcp->source);
                     sniff_data_to_ettercap.dest_port = ntohs(tcp->dest);
                     sniff_data_to_ettercap.seq = ntohl(tcp->seq);
                     sniff_data_to_ettercap.ack_seq = ntohl(tcp->ack_seq);
                     sniff_data_to_ettercap.flags = tcp->flags;
                     sniff_data_to_ettercap.proto = 'T';
                     sniff_data_to_ettercap.datasize = tcp_datalen;
                     memset(&sniff_data_to_ettercap.data, 0, sizeof(sniff_data_to_ettercap.data));
                     memcpy(&sniff_data_to_ettercap.data, tcp_data, tcp_datalen);
#ifdef PERMIT_PLUGINS
                     Plugin_HookPoint(PCK_RECEIVED_STRUCT_FILLED, &sniff_data_to_ettercap);     // HOOK POINT: PCK_RECEIVED_STRUCT_FILLED
#endif
                  }

                  dontforward = Dissector_Connections( ((illithid_param *)param)->mode, IPPROTO_TCP, (u_char *)tcp, &data_to_ettercap, &sniff_data_to_ettercap, Act_Connection_Mode);

                  dissector_data.layer4 = (u_char *)tcp;
                  dissector_data.connection = &data_to_ettercap;
#ifdef PERMIT_PLUGINS
                  Plugin_HookPoint(PCK_DISSECTOR, &dissector_data);     // HOOK POINT: PCK_DISSECTOR
#endif
                  if (!dontforward) Illithid_Decoder_Put(&data_to_ettercap);

                  if (!Act_Connection_Mode)
                  {
#ifdef PERMIT_PLUGINS
                     Plugin_HookPoint(PCK_DECODED, &sniff_data_to_ettercap);     // HOOK POINT: PCK_DECODED
#endif
                     if (!dontforward && Illithid_ToBeSniffed(&sniff_data_to_ettercap))
                        Buffer_Put(pipe_with_illithid_data, &sniff_data_to_ettercap, sizeof(SNIFFED_DATA));
                  }
               }
            }

            if ( PckDir && ip->proto == IPPROTO_UDP)
            {
               unsigned char *udp_data;
               int udp_datalen;
               udp = (UDP_header *) ((int)ip + ip->h_len * 4);

               if (!( ntohs(ip->frag_and_flags) & IP_OFFMASK))
               {
                  DISSECTION dissector_data;

                  udp_data = (char *)((int)udp + UDP_HEADER);
                  udp_datalen = ntohs(udp->len) - UDP_HEADER;

                  if (udp_datalen < 0 || udp_datalen > len) goto send;

						udp_datalen = (udp_datalen > MAX_DATA) ? MAX_DATA : udp_datalen;   // don't accept bogus sized packets

                  data_to_ettercap.source_port = ntohs(udp->source);
                  data_to_ettercap.dest_port = ntohs(udp->dest);
                  data_to_ettercap.proto = 'U';
                  data_to_ettercap.datalen = udp_datalen;

                  if(!Act_Connection_Mode)
                  {
                     sniff_data_to_ettercap.source_port = ntohs(udp->source);
                     sniff_data_to_ettercap.dest_port = ntohs(udp->dest);
                     sniff_data_to_ettercap.proto = 'U';
                     sniff_data_to_ettercap.datasize = udp_datalen;
                     memset(&sniff_data_to_ettercap.data, 0, sizeof(sniff_data_to_ettercap.data));
                     memcpy(&sniff_data_to_ettercap.data, udp_data, udp_datalen);
#ifdef PERMIT_PLUGINS
                     Plugin_HookPoint(PCK_RECEIVED_STRUCT_FILLED, &sniff_data_to_ettercap);     // HOOK POINT: PCK_RECEIVED_STRUCT_FILLED
#endif
                  }

                  dontforward = Dissector_Connections( ((illithid_param *)param)->mode, IPPROTO_UDP, (u_char *)udp, &data_to_ettercap, &sniff_data_to_ettercap, Act_Connection_Mode);

                  dissector_data.layer4 = (u_char *)udp;
                  dissector_data.connection = &data_to_ettercap;
#ifdef PERMIT_PLUGINS
                  Plugin_HookPoint(PCK_DISSECTOR, &dissector_data);     // HOOK POINT: PCK_DISSECTOR
#endif
                  if (!dontforward) Illithid_Decoder_Put(&data_to_ettercap);

                  if (!Act_Connection_Mode)
                  {
#ifdef PERMIT_PLUGINS
                     Plugin_HookPoint(PCK_DECODED, &sniff_data_to_ettercap);     // HOOK POINT: PCK_DECODED
#endif
                     if (!dontforward && Illithid_ToBeSniffed(&sniff_data_to_ettercap))
                        Buffer_Put(pipe_with_illithid_data, &sniff_data_to_ettercap, sizeof(SNIFFED_DATA));
                  }
               }
            }

            if (!dontforward && PckDir)
            {
               char Pck_Modified = 0;

               // --------- UDP FILTERING ----------
               if ( PckDir && ip->proto == IPPROTO_UDP )
               {
                  udp = (UDP_header *) ((int)ip + ip->h_len * 4);
                  if (ntohs(ip->frag_and_flags) & IP_OFFMASK) goto send;
                  datalen = ntohs(udp->len) - UDP_HEADER;

                  len -= ETH_HEADER;
                  if (PckDir == PCK_STOD || PckDir == PCK_ANY)
                  {
                     if (filter_on_source) delta = FilterDrop_MakefilterUDP((u_char *)ip, &len, MTU, Filter_Array_Source, &Pck_Modified);
                  }
                  else if (PckDir == PCK_DTOS || PckDir == PCK_ANY)
                  {
                     if (filter_on_dest) delta = FilterDrop_MakefilterUDP((u_char *)ip, &len, MTU, Filter_Array_Dest, &Pck_Modified);
                  }
                  len += ETH_HEADER;

                  if (delta && Pck_Modified == MOD_REPLACED)  // checksum needs to be recalculated
                  {
                     ip->checksum = 0;
                     ip->checksum = Inet_Forge_ChecksumIP( (u_short *)ip, sizeof(IP_header) );
                  }
                  if (Pck_Modified == MOD_REPLACED)
                  {
                     udp->checksum = 0;
                     udp->checksum = Inet_Forge_Checksum( (u_short *)udp, IPPROTO_UDP, UDP_HEADER+datalen, ip->source_ip, ip->dest_ip );
                  }

                  if (Pck_Modified == MOD_DROP) PckDir = PCK_DROP;  // drop the packet (forwarding is done only if(PckDir) )
               }

               // --------- TCP FILTERING ----------
               if ( PckDir && ip->proto == IPPROTO_TCP )
               {
                  Ielem **saved_session;
                  Ielem session;

                  tcp = (TCP_header *) ((int)ip + ip->h_len * 4);
                  if (ntohs(ip->frag_and_flags) & IP_OFFMASK) goto send;
                  data = (char *)((int)tcp + tcp->doff * 4);

                  datalen = (int)ip + ntohs(ip->t_len) - (int)data; // I need it before modifications....

                  len -= ETH_HEADER;
                  if (PckDir == PCK_STOD || PckDir == PCK_ANY)
                  {
                     if (filter_on_source) delta = FilterDrop_MakefilterTCP((u_char *)ip, &len, MTU, Filter_Array_Source, &Pck_Modified);
                  }
                  if (PckDir == PCK_DTOS || PckDir == PCK_ANY)
                  {
                     if (filter_on_dest) delta = FilterDrop_MakefilterTCP((u_char *)ip, &len, MTU, Filter_Array_Dest, &Pck_Modified);
                  }
                  len += ETH_HEADER;
// FIXME
                  saved_session = Illithid_Find_Session(ip->source_ip,ip->dest_ip,tcp->source,tcp->dest,ip->proto, &session);

                  session.elem1.datalen = datalen;
                  session.elem1.Seq = ntohl(tcp->seq);
                  session.elem1.Ack = ntohl(tcp->ack_seq);
                  memcpy(session.elem1.MAC,data_to_ettercap.source_mac,6);
                  session.elem1.IPID = ntohs(ip->ident);
                  session.elem1.flags |= tcp->flags;

                  if (((illithid_param *)param)->mode==ARPBASED)
                  {
                     tcp->seq = htonl(session.elem1.Seq+session.elem1.ByteSent);
                     tcp->ack_seq = htonl(session.elem1.Ack-session.elem2.ByteSent);
                     ip->ident = htons(session.elem1.IPID+session.elem1.PacketSent);

                     if (Pck_Modified == MOD_DROP)     // the packet must be dropped, so we send an ACK
                     {
                        char *pck_to_send;

                        if (datalen != 0)
                        {
                           pck_to_send = ins_pck;
                           pck_to_send += Inet_Forge_ethernet( pck_to_send, MyMAC, data_to_ettercap.source_mac, ETH_P_IP );
                           pck_to_send += Inet_Forge_ip( pck_to_send, ip->dest_ip, ip->source_ip, TCP_HEADER, session.elem2.IPID+session.elem2.PacketSent+1, 0, IPPROTO_TCP);
                           pck_to_send += Inet_Forge_tcp( pck_to_send, ntohs(tcp->dest), ntohs(tcp->source), ntohl(tcp->ack_seq), session.elem1.Seq+session.elem1.datalen, TH_ACK, 0, 0);

                           Inet_SendRawPacket(sock, ins_pck, pck_to_send-ins_pck);
                           session.elem2.PacketSent++;
                        }
                        PckDir = PCK_DROP;  // drop the packet (forwarding is done only if(PckDir) )
                     }

                     session.elem1.ByteSent += delta;
                     session.elem1.datalen = (int)ip + ntohs(ip->t_len) - (int)data; // now i store the modified datalen

                     if ((delta && Pck_Modified == MOD_REPLACED) || (PckDir && session.elem1.PacketSent))
                     {
                        ip->checksum = 0;
                        ip->checksum = Inet_Forge_ChecksumIP( (unsigned short *) ip, sizeof(IP_header));
                     }

                     if (Pck_Modified == MOD_REPLACED || (PckDir && (session.elem1.ByteSent || session.elem2.ByteSent)))
                     {
                        tcp->checksum = 0;
                        tcp->checksum = Inet_Forge_Checksum((unsigned short *)tcp, IPPROTO_TCP, ntohs(ip->t_len)-ip->h_len*4, ip->source_ip, ip->dest_ip);
                     }
                  } // endif ARPBASED

                  if (((illithid_param *)param)->mode <= PUBLICARP && PckDir && !dontforward)
                  {
#ifdef PERMIT_PLUGINS
                     Plugin_HookPoint(PCK_PRE_FORWARD, buffer);      // HOOK POINT: PCK_PRE_FORWARD
#endif
                     session.elem1.PacketSent += Inet_SendLargeTCPPacket(sock, buffer, len, MTU);
                  }
                  Illithid_Set_Session(saved_session, &session, ((illithid_param *)param)->mode);
                  goto nosend;
               } //endif TCP filtering
            } //endif !dontforward

send:       if (((illithid_param *)param)->mode <= PUBLICARP && PckDir && !dontforward)
            {
#ifdef PERMIT_PLUGINS
               Plugin_HookPoint(PCK_PRE_FORWARD, buffer);      // HOOK POINT: PCK_PRE_FORWARD
#endif
               Inet_SendRawPacket(sock, buffer, len);
            }
nosend:     while(0);      // dirty trick to avoid warning....
         } // endif ETH_P_IP
      }  // endif len > 0
      else
         usleep(1000);

// ==========================================================================
      {
         KILL_DATA to_kill;
         nchars = read(pipe_kill[0], &to_kill, sizeof(KILL_DATA));
         if (nchars == sizeof(KILL_DATA))
         {
            char *buf;
            Ielem **saved_session;
            Ielem session;

            #ifdef DEBUG
               Debug_msg("Illithid_GetConnections -- KILL A CONNECTION");
            #endif

            saved_session = Illithid_Find_Session(to_kill.source_ip, to_kill.dest_ip, to_kill.source_port, to_kill.dest_port, IPPROTO_TCP, &session);


            buf = Inet_Forge_packet( ETH_HEADER + IP_HEADER + TCP_HEADER );

            Inet_Forge_ethernet( buf, MyMAC, session.elem2.MAC, ETH_P_IP );
            Inet_Forge_ip( buf + ETH_HEADER, session.elem1.IP, session.elem2.IP,
                                             TCP_HEADER,
                                             session.elem1.IPID + session.elem1.PacketSent + 1,
                                             0, IPPROTO_TCP );
            Inet_Forge_tcp( buf + ETH_HEADER + IP_HEADER, ntohs(session.elem1.Port),
                                                          ntohs(session.elem2.Port),
                                                          session.elem1.Seq + session.elem1.datalen + session.elem1.ByteSent,
                                                          0,
                                                          TH_RST,
                                                          0, 0 );

            Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + TCP_HEADER );

            Inet_Forge_ethernet( buf, MyMAC, session.elem1.MAC, ETH_P_IP );
            Inet_Forge_ip( buf + ETH_HEADER, session.elem2.IP, session.elem1.IP,
                                             TCP_HEADER,
                                             session.elem2.IPID + session.elem2.PacketSent + 1,
                                             0, IPPROTO_TCP );
            Inet_Forge_tcp( buf + ETH_HEADER + IP_HEADER, ntohs(session.elem2.Port),
                                                          ntohs(session.elem1.Port),
                                                          session.elem2.Seq + session.elem2.datalen + session.elem2.ByteSent,
                                                          0,
                                                          TH_RST,
                                                          0, 0 );

            Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + TCP_HEADER );

            Inet_Forge_packet_destroy( buf );

         }
      }

// ==========================================================================

      if (((illithid_param *)param)->mode==ARPBASED)
      {
         INJECTED_DATA inj;

         nchars = read(pipe_inject[0], &inj, sizeof(INJECTED_DATA));

         if (nchars == sizeof(INJECTED_DATA))
         {
            char *pck_to_send = ins_pck;
            Ielem **saved_session = NULL;
            Ielem session;

            #ifdef DEBUG
               Debug_msg("Illithid_GetConnections -- INJECT");
            #endif

            if (inj.proto == 'T')
            {
               saved_session = Illithid_Find_Session(inj.source_ip, inj.dest_ip, inj.source_port, inj.dest_port, IPPROTO_TCP, &session);

               pck_to_send += Inet_Forge_ethernet( pck_to_send, MyMAC, session.elem2.MAC, ETH_P_IP );

               pck_to_send += Inet_Forge_ip( pck_to_send, session.elem1.IP, session.elem2.IP,
                                                          TCP_HEADER + inj.datalen,
                                                          session.elem1.IPID + session.elem1.PacketSent + 1,
                                                          0, IPPROTO_TCP);

               pck_to_send += Inet_Forge_tcp( pck_to_send, ntohs(session.elem1.Port),
                                                           ntohs(session.elem2.Port),
                                                           session.elem1.Seq + session.elem1.datalen + session.elem1.ByteSent,
                                                           session.elem1.Ack - session.elem2.ByteSent,
                                                           TH_PSH | TH_ACK,
                                                           inj.data, inj.datalen);

            }
            else if (inj.proto == 'U')
            {
               saved_session = Illithid_Find_Session(inj.source_ip, inj.dest_ip, inj.source_port, inj.dest_port, IPPROTO_UDP, &session);

               pck_to_send += Inet_Forge_ethernet( pck_to_send, MyMAC, session.elem2.MAC, ETH_P_IP );

               pck_to_send += Inet_Forge_ip( pck_to_send, session.elem1.IP, session.elem2.IP,
                                                          TCP_HEADER + inj.datalen,
                                                          session.elem1.IPID + session.elem1.PacketSent + 1,
                                                          0, IPPROTO_UDP);

               pck_to_send += Inet_Forge_udp( pck_to_send, ntohs(session.elem1.Port),
                                                           ntohs(session.elem2.Port),
                                                           inj.data, inj.datalen);
            }

            Inet_SendRawPacket(sock, ins_pck, pck_to_send-ins_pck);

            session.elem1.ByteSent += inj.datalen;
            session.elem1.PacketSent++;

            Illithid_Set_Session(saved_session, &session, ((illithid_param *)param)->mode);
         }
      }
//==================================================================

   } // end loop

   exit_func_end();

}


int Illithid_ToBeSniffed(SNIFFED_DATA *data)
{
   char s=0, ps=0, d=0, pd=0;

   if (current_illithid_data.proto != data->proto) return 0;

   if (current_illithid_data.source_port == 0) ps = 1;
   if (current_illithid_data.dest_port == 0) pd = 1;
   if (current_illithid_data.source_ip == 0) s = 1;
   if (current_illithid_data.dest_ip == 0) d = 1;

   if (s || current_illithid_data.source_ip == data->fast_source_ip)
      if (ps || current_illithid_data.source_port == data->source_port)
      {  s = 1;   ps = 1;  }

   if (s || current_illithid_data.source_ip == data->fast_dest_ip)
      if (ps || current_illithid_data.source_port == data->dest_port)
      {  s = 1;   ps = 1;  }

   if (d || current_illithid_data.dest_ip == data->fast_source_ip)
      if (pd || current_illithid_data.dest_port == data->source_port)
      {  d = 1;   pd = 1;  }

   if (d || current_illithid_data.dest_ip == data->fast_dest_ip)
      if (pd || current_illithid_data.dest_port == data->dest_port)
      {  d = 1;   pd = 1;  }

   return ( Options.reverse ^ (s && ps && d && pd) );
}


int Illithid_ToBeSniffed_ip(u_long source, u_long dest, CONNECTION *data)
{
   char s=0, d=0;

   if (source == 0) s = 1;
   if (dest == 0) d = 1;

   if (s && d) return(PCK_ANY);

   if ( (s || Options.reverse ^(source == data->fast_source_ip) ) &&
        (d || Options.reverse ^(dest == data->fast_dest_ip) ) ) return (PCK_STOD);

   if ( (s || Options.reverse ^(source == data->fast_dest_ip) ) &&
        (d || Options.reverse ^(dest == data->fast_source_ip) ) ) return (PCK_DTOS);

   return (0);

}

int Illithid_ToBeSniffed_mac(char *source, char *dest, CONNECTION *data)
{
   char s=0, d=0;

   if (!memcmp(source, "\0\0\0\0\0\0", 6)) s = 1;
   if (!memcmp(dest, "\0\0\0\0\0\0", 6)) d = 1;

   if (s && d) return(PCK_ANY);

   if ( (s || !memcmp(data->source_mac, source, 6)) &&
        (d || !memcmp(data->dest_mac, dest, 6)) ) return (PCK_STOD);

   if ( (s || !memcmp(data->dest_mac, source, 6)) &&
        (d || !memcmp(data->source_mac, dest, 6)) ) return (PCK_DTOS);

   return (0);

}


Ielem **Illithid_Find_Session(unsigned int IP1, unsigned int IP2, unsigned short Port1, unsigned short Port2, char proto, Ielem *outs)
{
   Ielem **to_find;
   unsigned char hash, found=0;
   static short rand_id=0;


   hash = (htonl(IP1)+htonl(IP2)+htons(Port1)+htons(Port2))%HASHES; // Very simple hash
   to_find = &(hash_table[hash]);

   while (*to_find)
   {
      if (proto==(*to_find)->proto)
      {
         if ((*to_find)->elem1.IP==IP1 && (*to_find)->elem2.IP==IP2 &&
             (*to_find)->elem1.Port==Port1 && (*to_find)->elem2.Port==Port2)
         {
            found = 1;
            break;
         }

         if ((*to_find)->elem1.IP==IP2 && (*to_find)->elem2.IP==IP1 &&
             (*to_find)->elem1.Port==Port2 && (*to_find)->elem2.Port==Port1)
         {
            found = 2;
            break;
         }
      }
      to_find = (Ielem **)&((*to_find)->next);
   }

   outs->proto = proto;

   if (found == 1)
   {
      memcpy (&(outs->elem1), &((*to_find)->elem1), sizeof(side_elem));
      memcpy (&(outs->elem2), &((*to_find)->elem2), sizeof(side_elem));
   }
   else if (found == 2)
   {
      memcpy (&(outs->elem1), &((*to_find)->elem2), sizeof(side_elem));
      memcpy (&(outs->elem2), &((*to_find)->elem1), sizeof(side_elem));
   }
   else if (found == 0)
   {
      memset (&(outs->elem1), 0, sizeof(side_elem));
      memset (&(outs->elem2), 0, sizeof(side_elem));

      outs->elem1.IP   = IP1;
      outs->elem1.Port = Port1;
      outs->elem1.IPID = hash+rand_id++;  // Don't care about it

      outs->elem2.IP   = IP2;
      outs->elem2.Port = Port2;
      outs->elem2.IPID = outs->elem1.IPID;

      if (!Options.normal)
      {
         Ielem *new_elem;
         new_elem = malloc(sizeof(Ielem));

         if (!new_elem) return (to_find);

         new_elem->proto = outs->proto;
         memcpy(&(new_elem->elem1), &(outs->elem1), sizeof(side_elem));
         memcpy(&(new_elem->elem2), &(outs->elem2), sizeof(side_elem));
         new_elem->next = (struct Ielem*)hash_table[hash];
         hash_table[hash] = new_elem;
         to_find = &(hash_table[hash]);

         #ifdef DEBUG
            Debug_msg("Illithid_Find_Session -- CREATE NEW SESSION");
         #endif
      }
   }
   return (to_find);
}

void Illithid_Set_Session(Ielem **session, Ielem *outs, short mode)
{
   if (*session)
   {
      if (
           (outs->elem1.flags & TH_RST) ||
           ( (outs->elem1.flags & TH_ACK) && ( ((*session)->elem1.flags && (*session)->elem2.flags )) ) ||
           ( (outs->elem1.flags & TH_FIN) && mode==PUBLICARP )
         )
      // Hey, cool! what a mess....
      {
         Ielem *temp;

         #ifdef DEBUG
            Debug_msg("Illithid_Set_Session -- DELETE AN OLD SESSION");
         #endif

         temp = (Ielem *)((*session)->next);
         free(*session);
         *session = temp;
         return;
      }

      outs->elem1.flags &= TH_FIN;
      outs->elem2.flags &= TH_FIN;

      if ((*session)->elem1.IP == outs->elem1.IP)
      {
         memcpy (&((*session)->elem1), &(outs->elem1), sizeof(side_elem));
         memcpy (&((*session)->elem2), &(outs->elem2), sizeof(side_elem));

      }
      else
      {
         memcpy (&((*session)->elem1), &(outs->elem2), sizeof(side_elem));
         memcpy (&((*session)->elem2), &(outs->elem1), sizeof(side_elem));
      }
   }
   else if (outs->elem1.ByteSent /* || outs->elem2.ByteSent */)
   {
      Ielem *new_elem;
      unsigned char hash;

      hash = (htonl(outs->elem1.IP)+htonl(outs->elem2.IP)+htons(outs->elem1.Port)+htons(outs->elem2.Port))%HASHES; // Very simple hash
      new_elem = malloc(sizeof(Ielem));

      if (!new_elem) return;

      new_elem->proto = outs->proto;
      outs->elem1.flags &= TH_FIN;
      outs->elem2.flags &= TH_FIN;
      memcpy(&(new_elem->elem1), &(outs->elem1), sizeof(side_elem));
      memcpy(&(new_elem->elem2), &(outs->elem2), sizeof(side_elem));
      new_elem->next = (struct Ielem*)hash_table[hash];
      hash_table[hash] = new_elem;
   }
}


void Illithid_Reset_Conn(void *dummy)
{
   int i,j;
   Ielem *session, *next;
   char *buf1, *buf2, *pck_to_send;

#ifdef DEBUG
   Debug_msg("Illithid_Reset_Conn");
#endif

   for (j=0; j<HASHES; j++)
   {
      session=hash_table[j];
      while (session)
      {
         next = (Ielem *)session->next;

         if (session->elem1.ByteSent || session->elem2.ByteSent)
         {
            buf1 = Inet_Forge_packet( ETH_HEADER + IP_HEADER + TCP_HEADER );
            pck_to_send = buf1;
            pck_to_send += Inet_Forge_ethernet( pck_to_send, MyMAC, session->elem2.MAC, ETH_P_IP );
            pck_to_send += Inet_Forge_ip( pck_to_send, session->elem1.IP,
                                                       session->elem2.IP,
                                                       TCP_HEADER,
                                                       session->elem1.IPID+session->elem1.PacketSent+1,
                                                       0, IPPROTO_TCP);
            pck_to_send += Inet_Forge_tcp( pck_to_send, ntohs(session->elem1.Port),
                                                        ntohs(session->elem2.Port),
                                                        session->elem1.Seq+session->elem1.datalen+session->elem1.ByteSent,
                                                        0,
                                                        TH_RST, 0, 0);

            buf2 = Inet_Forge_packet( ETH_HEADER + IP_HEADER + TCP_HEADER );
            pck_to_send = buf2;
            pck_to_send += Inet_Forge_ethernet( pck_to_send, MyMAC, session->elem1.MAC, ETH_P_IP );
            pck_to_send += Inet_Forge_ip( pck_to_send, session->elem2.IP,
                                                       session->elem1.IP,
                                                       TCP_HEADER,
                                                       session->elem2.IPID+session->elem2.PacketSent+1,
                                                       0, IPPROTO_TCP);
            pck_to_send += Inet_Forge_tcp( pck_to_send, ntohs(session->elem2.Port),
                                                        ntohs(session->elem1.Port),
                                                        session->elem2.Seq+session->elem2.datalen+session->elem2.ByteSent,
                                                        0,
                                                        TH_RST, 0, 0);

            for(i=0; i<2; i++)
            {
               Inet_SendRawPacket(sock, buf1, ETH_HEADER + IP_HEADER + TCP_HEADER );
               Inet_SendRawPacket(sock, buf2, ETH_HEADER + IP_HEADER + TCP_HEADER );
               usleep(1000);
            }
         }

         free(session);
         session = next;
      }
      hash_table[j] = 0;
   }

   ECThread_destroy(decoder_pid);

   Buffer_Flush(illithid_buffer);

#ifdef DEBUG
   Debug_msg("Illithid -- ShutDowned gracefully...");
#endif

}


/* EOF */

