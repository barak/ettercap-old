/*
    ettercap -- the protocol dissector

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

    $Id: ec_dissector.c,v 1.12 2002/01/22 21:23:01 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_decodedata.h"
#include "include/ec_error.h"

#define ALL_P 0


struct state_machine   // state machine double linked list for some protocol dissector
{
   pthread_t id;
   time_t timeout;
   long source_ip;
   long dest_ip;
   u_short source_port;
   u_short dest_port;
   char proto;
   char state;
   char info[20];
   LIST_ENTRY (state_machine) next;
};


LIST_HEAD(, state_machine) SM_head;


DISSECTOR Available_Dissectors[] = {

   {MACBASED,  IPPROTO_TCP,    21, &Dissector_ftp,       1, "FTP"},
#ifdef HAVE_OPENSSL
   {ARPBASED,  IPPROTO_TCP,    22, &Dissector_ssh,       1, "SSH"},
#endif
   {MACBASED,  IPPROTO_TCP,    23, &Dissector_telnet,    1, "TELNET"},
   {MACBASED,  IPPROTO_TCP,    80, &Dissector_http,      1, "HTTP"},
   {MACBASED,  IPPROTO_TCP,   110, &Dissector_pop,       1, "POP"},
   {MACBASED,  IPPROTO_TCP,   111, &Dissector_portmapTCP,1, "RPC"},
   {MACBASED,  IPPROTO_UDP,   111, &Dissector_portmapUDP,1, "RPC"},
   {MACBASED,  IPPROTO_TCP,   119, &Dissector_nntp,      1, "NNTP"},
   {MACBASED,  IPPROTO_TCP,   139, &Dissector_smb,       1, "SMB"},
   {MACBASED,  IPPROTO_TCP,   143, &Dissector_imap,      1, "IMAP"},
   {MACBASED,  IPPROTO_UDP,   161, &Dissector_snmp,      1, "SNMP"},
   {MACBASED,  IPPROTO_TCP,   179, &Dissector_bgp,       1, "BGP"},
   {MACBASED,  IPPROTO_TCP,   220, &Dissector_imap,      1, "IMAP"},
   {MACBASED,  IPPROTO_TCP,   389, &Dissector_ldap,      1, "LDAP"},
#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
   {PUBLICARP, IPPROTO_TCP,   443, &Dissector_https,     1, "HTTPS"},
#endif
   {MACBASED,  IPPROTO_TCP,   512, &Dissector_rlogin,    1, "RLOGIN"},
   {MACBASED,  IPPROTO_TCP,   513, &Dissector_rlogin,    1, "RLOGIN"},
   {MACBASED,  IPPROTO_TCP,   514, &Dissector_rlogin,    1, "RLOGIN"},
   {MACBASED,  IPPROTO_UDP,   520, &Dissector_rip,       1, "RIP"},
#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
   {PUBLICARP, IPPROTO_TCP,  HTTPS_Local_Port, &Dissector_https,     1, "REVHTTPS"},
   {PUBLICARP, IPPROTO_TCP,  Proxy_Local_Port, &Dissector_https,     1, "REVHTTPS"},
#endif
   {MACBASED,  IPPROTO_TCP,  1080, &Dissector_socks,     1, "SOCKS"},
   {MACBASED,  IPPROTO_TCP,  3306, &Dissector_mysql,     1, "MYSQL"},
   {MACBASED,  IPPROTO_UDP,  4000, &Dissector_icq,       1, "ICQ"},
   {MACBASED,  IPPROTO_UDP,  5190, &Dissector_icq,       1, "ICQ"},
   {MACBASED,  IPPROTO_TCP,  5900, &Dissector_vnc,       1, "VNC"},
   {MACBASED,  IPPROTO_TCP,  5901, &Dissector_vnc,       1, "VNC"},
   {MACBASED,  IPPROTO_TCP,  5902, &Dissector_vnc,       1, "VNC"},
   {MACBASED,  IPPROTO_TCP,  5903, &Dissector_vnc,       1, "VNC"},
   {MACBASED,  IPPROTO_TCP,  5904, &Dissector_vnc,       1, "VNC"},
   {MACBASED,  IPPROTO_TCP,  6000, &Dissector_x11,       1, "X11"},
   {MACBASED,  IPPROTO_TCP,  6001, &Dissector_x11,       1, "X11"},
   {MACBASED,  IPPROTO_TCP,  6002, &Dissector_x11,       1, "X11"},
   {MACBASED,  IPPROTO_TCP,  6003, &Dissector_x11,       1, "X11"},
   {MACBASED,  IPPROTO_TCP,  6004, &Dissector_x11,       1, "X11"},
   {MACBASED,  IPPROTO_TCP,  6666, &Dissector_napster,   1, "NAPSTER"},
   {MACBASED,  IPPROTO_TCP,  6667, &Dissector_irc,       1, "IRC"},
   {MACBASED,  IPPROTO_TCP,  6668, &Dissector_irc,       1, "IRC"},
   {MACBASED,  IPPROTO_TCP,  6669, &Dissector_irc,       1, "IRC"},
   {MACBASED,  IPPROTO_TCP,  7777, &Dissector_napster,   1, "NAPSTER"},
#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
   {PUBLICARP, IPPROTO_TCP,  8080, &Dissector_https,     1, "PROXYHTTPS"},    // for proxies https
#endif
   {MACBASED,  IPPROTO_TCP,  8080, &Dissector_http,      1, "HTTP"},          // for proxies
   {MACBASED,  IPPROTO_TCP,  8888, &Dissector_napster,   1, "NAPSTER"},
   {MACBASED,  IPPROTO_UDP, 27015, &Dissector_hl_rcon,   1, "HL-RCON"},
   {MACBASED,  IPPROTO_TCP, 65301, &Dissector_pcanywhere,1, "PCANYWHERE"},
   {MACBASED,  IPPROTO_UDP, ALL_P, &Dissector_icq,       1, "ICQ"},
   {       0,            0,     0,                 NULL, 0, ""}
};

RPC_DISSECTOR Available_RPC_Dissectors[] = {
   {100005,  1, IPPROTO_TCP, &Dissector_mountdTCP, NULL},
   {100005,  1, IPPROTO_UDP, &Dissector_mountdUDP, NULL},
   {100005,  2, IPPROTO_TCP, &Dissector_mountdTCP, NULL},
   {100005,  2, IPPROTO_UDP, &Dissector_mountdUDP, NULL},
   {100005,  3, IPPROTO_TCP, &Dissector_mountdTCP, NULL},
   {100005,  3, IPPROTO_UDP, &Dissector_mountdUDP, NULL},
   {     0,  0,           0, NULL,                 NULL}
};

// protos....

int Dissector_Connections( char mode, short proto, u_char *data, CONNECTION *data_to_ettercap, SNIFFED_DATA *sniff_data_to_ettercap, int Conn_Mode );
void Dissector_SetHandle( char *name, char active, short port, short proto);
int Dissector_StateMachine_GetStatus(CONNECTION *data_to_ettercap, char *info);
int Dissector_StateMachine_SetStatus(CONNECTION *data_to_ettercap, char status, char *info);
int Dissector_base64decode(char *bufplain, const char *bufcoded);  // stolen from ap_base64.c part of apache source code

// -------------------------------------


int Dissector_Connections( char mode, short proto, u_char *data, CONNECTION *data_to_ettercap, SNIFFED_DATA *sniff_data_to_ettercap, int Conn_Mode )
{

   TCP_header *tcp;
   UDP_header *udp;
   DISSECTOR *ds;
   RPC_DISSECTOR *rds;

   switch(proto)
   {
      case IPPROTO_TCP:
                        tcp = (TCP_header *) data;

                        for( ds = Available_Dissectors; ds->dissector != NULL; ds++)
                        {
                           if ( ds->active && (ntohs(tcp->source) == ds->port || ntohs(tcp->dest) == ds->port || ds->port == ALL_P)
                             && ds->proto == IPPROTO_TCP && mode <= ds->mode  )
                           {
                              if (ds->mode <= PUBLICARP)
                              {
                                 if (active_dissector)      // activated by user in iterface_sniff
                                    return ds->dissector(data, data_to_ettercap, sniff_data_to_ettercap, Conn_Mode, ds->port);
                              }
                              else
                                 return ds->dissector(data, data_to_ettercap, sniff_data_to_ettercap, Conn_Mode, ds->port);

                              break;
                           }
                        }

                        for ( rds = Available_RPC_Dissectors;  rds->program != 0; rds ++)
                        {
                           if ( rds->proto == IPPROTO_TCP)
                           {
                              RPC_PORTS *ports;
                              ports = rds->ports;

                              while (ports)
                              {
                                 if (ports->port == ntohs(tcp->dest) || ports->port == ntohs(tcp->source))
                                    return rds->dissector(data, data_to_ettercap, sniff_data_to_ettercap, Conn_Mode, ports->port);

                                 ports = (RPC_PORTS *)ports->next;
                              }
                           }
                        }

                        break;
      case IPPROTO_UDP:
                        udp = (UDP_header *) data;

                        for( ds = Available_Dissectors; ds->dissector != NULL; ds++)
                        {
                           if ( ds->active && (ntohs(udp->source) == ds->port || ntohs(udp->dest) == ds->port || ds->port == ALL_P)
                             && ds->proto == IPPROTO_UDP && mode <= ds->mode  )
                           {
                              if (ds->mode <= PUBLICARP)
                              {
                                 if (active_dissector)      // activated by user in iterface_sniff
                                    return ds->dissector(data, data_to_ettercap, sniff_data_to_ettercap, Conn_Mode, ds->port);
                              }
                              else
                                 return ds->dissector(data, data_to_ettercap, sniff_data_to_ettercap, Conn_Mode, ds->port);

                              break;
                           }
                        }

                        for ( rds = Available_RPC_Dissectors;  rds->program != 0; rds ++)
                        {
                           if ( rds->proto == IPPROTO_UDP)
                           {
                              RPC_PORTS *ports;
                              ports = rds->ports;

                              while (ports)
                              {
                                 if (ports->port == ntohs(udp->dest) || ports->port == ntohs(udp->source))
                                    return rds->dissector(data, data_to_ettercap, sniff_data_to_ettercap, Conn_Mode, ports->port);

                                 ports = (RPC_PORTS *)ports->next;
                              }
                           }
                        }

                        break;
   }
   return 0;
}

void Dissector_SetHandle( char *name, char active, short port, short proto)
{
   DISSECTOR *ds;
   char found=0;

#ifdef DEBUG
   Debug_msg("\tDissector_SetHandle - %s %d %d %d", name, active, port, proto);
#endif

   for( ds = Available_Dissectors; ds->port != 0; ds++)
   {
      if (!strcasecmp(name, ds->name))
      {
         ds->active = active;
         found = 1;

         if (port)
            ds->port = port;

         if (proto)
            ds->proto = proto;
      }
   }

   if (!found) fprintf(stdout, "%11s... not compiled in ettercap !!\n", name);
}




int Dissector_StateMachine_GetStatus(CONNECTION *data_to_ettercap, char *info)
{
   struct state_machine *ptr;

   LIST_FOREACH(ptr, &SM_head, next)
   {
      if (ptr->timeout < time(NULL) - 600)      // remove old entries...
      {
         LIST_REMOVE(ptr, next);
         free(ptr);
         return 0;
      }

      if ( ptr->id == pthread_self() &&
           ptr->proto == data_to_ettercap->proto &&
           ((ptr->source_ip == inet_addr(data_to_ettercap->source_ip) &&     // straight
             ptr->dest_ip == inet_addr(data_to_ettercap->dest_ip) &&
             ptr->source_port == data_to_ettercap->source_port &&
             ptr->dest_port == data_to_ettercap->dest_port)
             ||
             (ptr->source_ip == inet_addr(data_to_ettercap->dest_ip) &&       // reverse
             ptr->dest_ip == inet_addr(data_to_ettercap->source_ip) &&
             ptr->source_port == data_to_ettercap->dest_port &&
             ptr->dest_port == data_to_ettercap->source_port))
         )
      {
         if (info != NULL) strlcpy(info, ptr->info, 20);
         return ptr->state;
      }
   }
   return 0;
}


int Dissector_StateMachine_SetStatus(CONNECTION *data_to_ettercap, char status, char *info)
{
   struct state_machine *ptr, *current;

   LIST_FOREACH(ptr, &SM_head, next)
   {
      if (ptr->timeout < time(NULL) - 600)      // remove old entries...
      {
         LIST_REMOVE(ptr, next);
         free(ptr);
         return 0;
      }
      if ( ptr->id == pthread_self() &&
           ptr->proto == data_to_ettercap->proto &&
           ((ptr->source_ip == inet_addr(data_to_ettercap->source_ip) &&     // straight
             ptr->dest_ip == inet_addr(data_to_ettercap->dest_ip) &&
             ptr->source_port == data_to_ettercap->source_port &&
             ptr->dest_port == data_to_ettercap->dest_port)
             ||
             (ptr->source_ip == inet_addr(data_to_ettercap->dest_ip) &&       // reverse
             ptr->dest_ip == inet_addr(data_to_ettercap->source_ip) &&
             ptr->source_port == data_to_ettercap->dest_port &&
             ptr->dest_port == data_to_ettercap->source_port))
          )
      {
         #ifdef DEBUG
            Debug_msg("\tDissector_StateMachine_SetStatus - (%d)! %c %s:%d - %s:%d -- [%s]",
                        status, data_to_ettercap->proto,
                        data_to_ettercap->source_ip,
                        data_to_ettercap->source_port,
                        data_to_ettercap->dest_ip,
                        data_to_ettercap->dest_port,
                        info);
         #endif
         if (status)
         {
            ptr->timeout = time(NULL);
            ptr->state = status;
            if (info != NULL) strlcpy(ptr->info, info, 20);
            return 0;
         }
         else
         {
            LIST_REMOVE(ptr, next);
            free(ptr);
         }
         return 0;
      }
   }

   if (status)
   {
      #ifdef DEBUG
         Debug_msg("\tDissector_StateMachine_SetStatus - new item - state (%d)! %c %s:%d - %s:%d -- [%s]",
                      status, data_to_ettercap->proto,
                      data_to_ettercap->source_ip,
                      data_to_ettercap->source_port,
                      data_to_ettercap->dest_ip,
                      data_to_ettercap->dest_port,
                      info);
      #endif

      current = (struct state_machine *)calloc(1, sizeof(struct state_machine));
      if (current == NULL)
         ERROR_MSG("calloc()");

      current->id = pthread_self();
      current->timeout = time(NULL);
      current->source_ip = inet_addr(data_to_ettercap->source_ip);
      current->dest_ip = inet_addr(data_to_ettercap->dest_ip);
      current->source_port = data_to_ettercap->source_port;
      current->dest_port = data_to_ettercap->dest_port;
      current->proto = data_to_ettercap->proto;
      current->state = status;
      if (info != NULL) strlcpy(current->info, info, 20);

      LIST_INSERT_HEAD(&SM_head, current, next);
   }
   return 0;
}


// lines below stolen from ap_base64.c (apache source code)... ;)

static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};


int Dissector_base64decode(char *bufplain, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4)
    {
      *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
      *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
      *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
      bufin += 4;
      nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1)
      *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);

    if (nprbytes > 2)
      *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);

    if (nprbytes > 3)
      *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);

    nbytesdecoded -= (4 - nprbytes) & 3;

    bufplain[nbytesdecoded] = '\0';
    return nbytesdecoded;
}


/* EOF */
