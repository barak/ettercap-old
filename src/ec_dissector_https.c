/*
    ettercap -- dissector HTTPS -- TCP 443 (see ec_grell.c)

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

    $Id: ec_dissector_https.c,v 1.3 2001/11/19 09:30:22 alor Exp $
*/

#include "include/ec_main.h"

#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)


#include "include/ec_dissector.h"
#include "include/ec_inet_forge.h"
#include "include/ec_inet.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

extern int Grell_ProxyPort;

struct peer {
    u_short source_port;
    u_int   source_ip;
    u_short dest_port;
};

typedef struct {
    struct peer match;
    u_long  source_ip;
    u_long dest_ip;
    struct ssl_state *next;
} ssl_state;

ssl_state *ssl_conn=NULL;

// protos

FUNC_DISSECTOR(Dissector_https);

// --------------------------------------

FUNC_DISSECTOR(Dissector_https)
{
   TCP_header *tcp;
   static int initialized=0, sockraw, sockpck, MTU;
   static u_long MyIP;
   static char MyMAC[6];
   static struct sockaddr_in dest;
   u_int IPS, IPD;
   u_short PORTS, PORTD;
   u_long datalen;
   char buff[MAX_DATA];
   DATA_DISSECTOR;

   if (!initialized)
   {
      sockraw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
      sockpck = Inet_OpenRawSock(Options.netiface);
      Inet_GetIfaceInfo( Options.netiface, &MTU, MyMAC, &MyIP, NULL);

      Inet_SetRoute();
      Inet_SetARPEntry(inet_addr("1.0.0.1"), MyMAC);

      memset((char *)&dest, 0, sizeof(dest));
      dest.sin_family=AF_INET;
      initialized=1;
   }

   tcp = (TCP_header *) data;

   IPS = inet_addr(data_to_ettercap->source_ip);
   IPD = inet_addr(data_to_ettercap->dest_ip);
   PORTS = data_to_ettercap->source_port;
   PORTD = data_to_ettercap->dest_port;
   datalen = data_to_ettercap->datalen;

   if (PORTD==443 || PORTD==Grell_ProxyPort) // client side packets
   {
      ssl_state **index_ssl;
      struct peer pckpeer;
      char *pck_to_send;

      // Setting static-natted peer
      memset(&pckpeer,0,sizeof(pckpeer));
      pckpeer.source_port= PORTS;
      pckpeer.source_ip  = IPS & htonl(0x00ffffff);
      pckpeer.dest_port  = PORTD;

      // Find correct session
      index_ssl = &ssl_conn;
      while(*index_ssl != NULL && memcmp(&((*index_ssl)->match),&pckpeer,sizeof(pckpeer)))
      index_ssl = (ssl_state **)&((*index_ssl)->next);

      if (*index_ssl==NULL)
      {
          ssl_state *temp;

          if (!(tcp->flags & TH_SYN) || IPD==MyIP) return 0; // Not caught: forward
          temp = ssl_conn;

          ssl_conn = (ssl_state *)calloc(1, sizeof(ssl_state));
          memcpy(&(ssl_conn->match), &pckpeer, sizeof(pckpeer));
          ssl_conn->source_ip = IPS;
          ssl_conn->dest_ip = IPD;
          ssl_conn->next = (struct ssl_state *)temp;
      }

      IPD=MyIP;
      IPS=(IPS&htonl(0x00ffffff))|htonl(0x01000000);
      pck_to_send = buff;
      pck_to_send += Inet_Forge_ip( pck_to_send, IPS, IPD, (tcp->doff * 4)+datalen, 0xE77E, 0, IPPROTO_TCP);

      if (PORTD==443)
      {
          tcp->dest=htons(HTTPS_Local_Port);
          dest.sin_port=htons(HTTPS_Local_Port);
      }
      else
      {
          tcp->dest=htons(Proxy_Local_Port);
          dest.sin_port=htons(Proxy_Local_Port);
      }

      tcp->checksum=0;
      tcp->checksum=Inet_Forge_Checksum( (u_short *)tcp, IPPROTO_TCP, (tcp->doff * 4)+datalen, IPS, IPD);

      dest.sin_addr.s_addr = IPD;
      memcpy(pck_to_send, data, (tcp->doff * 4)+datalen);
      sendto(sockraw, buff, IP_HEADER + (tcp->doff * 4) + datalen, 0, (struct sockaddr *)&dest, sizeof(dest));
   }
   else
   if (PORTS==HTTPS_Local_Port || PORTS==Proxy_Local_Port) // server side packets
   {
      ssl_state **index_ssl;
      struct peer pckpeer;
      char *DestMAC = NULL;
      char StaticMAC[6];
      char *pck_to_send;
      int i;

      if ( (IPD & htonl(0xff000000)) != htonl(0x01000000) )
          return 0;  // Not caught: forward

      if (PORTS==HTTPS_Local_Port)
      {
          PORTS=443;
          tcp->source=htons(443);
      }
      else
      {
          PORTS=Grell_ProxyPort;
          tcp->source=htons(Grell_ProxyPort);
      }

      // Setting static-natted peer
      memset(&pckpeer,0,sizeof(pckpeer));
      pckpeer.source_port= PORTD;
      pckpeer.source_ip  = IPD & htonl(0x00ffffff);
      pckpeer.dest_port  = PORTS;

      // Find correct session
      index_ssl = &ssl_conn;
      while(*index_ssl != NULL && memcmp(&((*index_ssl)->match),&pckpeer,sizeof(pckpeer)))
      index_ssl = (ssl_state **)&((*index_ssl)->next);

      if (*index_ssl==NULL) return -1; // Oh my God!!! Where are you from????

      for(i = 1; i<number_of_hosts_in_lan; i++)
      {
         if (inet_addr(Host_In_LAN[i].ip) == (*index_ssl)->source_ip)
         {
            Inet_GetMACfromString(Host_In_LAN[i].mac, StaticMAC);
            DestMAC = StaticMAC;
            break;
         }
      }
      if (i>=number_of_hosts_in_lan)
         DestMAC = Inet_MacFromIP( (*index_ssl)->source_ip );

      pck_to_send = buff;
      pck_to_send += Inet_Forge_ethernet( pck_to_send, MyMAC, DestMAC, ETH_P_IP );
      pck_to_send += Inet_Forge_ip( pck_to_send, (*index_ssl)->dest_ip, (*index_ssl)->source_ip, (tcp->doff * 4)+datalen, 0xE77E, 0, IPPROTO_TCP);

      tcp->checksum=0;
      tcp->checksum=Inet_Forge_Checksum( (u_short *)tcp, IPPROTO_TCP, (tcp->doff * 4)+datalen,  (*index_ssl)->dest_ip, (*index_ssl)->source_ip);

      memcpy(pck_to_send, data, (tcp->doff * 4)+datalen);
      Inet_SendRawPacket(sockpck, buff, ETH_HEADER + IP_HEADER + (tcp->doff * 4) + datalen);
   }
   else
   {
      // Not Again!!!!!!!!!!!!!!
      // return 0;
   }

    return -1;  // dont forward and dont put in the buffer.
}

#endif

/* EOF */
