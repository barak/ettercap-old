/*
    basilisk -- ettercap plugin -- Checks if the poisoning had success

    Copyright (C) 2001  ALoR <alor@users.sourceforge.net>
                        NaGA <crwm@freemail.it>

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

    $Id: basilisk.c,v 1.3 2001/09/27 19:07:40 alor Exp $
*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"


// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int basilisk(void *dummy);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Checks if the poisoning had success",
   plug_version:     10,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &basilisk,
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

int basilisk(void *dummy)
{
   int sock, MTU, len=0, hnumb, i, j, notrecv=1;
   char *ReceivedS, *ReceivedD, *MACHosts, *pck;
   u_long MyIP, SpoofIP, *Hosts;
   ETH_header *eth;
   IP_header  *ip;
   ICMP_header *icmp;
   char SpoofMAC[6];
   char MyMAC[6];

   TIME_DECLARE;

   if ( number_of_connections == -1 )
   {
      Plugin_Output("\nYou have to use this plugin during an ARPBased poisoning session\n");
      return 0;
   }

   if ( !strcmp(Host_Source.ip, "") && !strcmp(Host_Dest.ip, "") )
   {
      Plugin_Output("\nYou have to select at least either source or dest ip.\n");
      return 0;
   }

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, MyMAC, &MyIP, NULL);

   fcntl(sock, F_SETFL, O_NONBLOCK);
   if (inet_addr(Host_Source.ip)!=-1)
   {
      SpoofIP=inet_addr(Host_Source.ip);
      Inet_GetMACfromString(Host_Source.mac, SpoofMAC);
   }
   else
   {
      SpoofIP=inet_addr(Host_Dest.ip);
      Inet_GetMACfromString(Host_Dest.mac, SpoofMAC);
   }

   if (inet_addr(Host_Source.ip)!=-1 && inet_addr(Host_Dest.ip)!=-1)
   {
       Hosts=calloc(1,sizeof(u_long));
       MACHosts=calloc(6,sizeof(char));
       Inet_GetMACfromString(Host_Dest.mac, MACHosts);
       Hosts[0]=inet_addr(Host_Dest.ip);
       hnumb=1;
   }
   else
   {
       Hosts=calloc(number_of_hosts_in_lan-2,sizeof(u_long));
       MACHosts=calloc(6*(number_of_hosts_in_lan-2),sizeof(char));
       for (i=j=0; i<number_of_hosts_in_lan; i++)
         if (inet_addr(Host_In_LAN[i].ip)!=SpoofIP && inet_addr(Host_In_LAN[i].ip)!=MyIP)
         {
            Hosts[j]=inet_addr(Host_In_LAN[i].ip);
            Inet_GetMACfromString(Host_In_LAN[i].mac, &MACHosts[j*6]);
             j++;
         }

       hnumb=number_of_hosts_in_lan-2;
   }

   ReceivedS=calloc(hnumb,sizeof(char));
   ReceivedD=calloc(hnumb,sizeof(char));

   pck=Inet_Forge_packet(MTU);

   for (i=0; i<hnumb; i++)
   {
      char *to_send;

      usleep(1500);
      to_send = pck;
      to_send += Inet_Forge_ethernet(to_send, MyMAC, SpoofMAC, ETH_P_IP);
      to_send += Inet_Forge_ip( to_send, Hosts[i], SpoofIP, ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP);
      icmp = (ICMP_header *) to_send;
      to_send += Inet_Forge_icmp( to_send, ICMP_ECHO, 0, NULL, 0);
      icmp->un.echo.seq = htons(i);
      icmp->un.echo.id = htons(0x570D);
      icmp->checksum = 0;
      icmp->checksum = Inet_Forge_ChecksumIP((u_short *)icmp, ICMP_HEADER);
      Inet_SendRawPacket(sock, pck, ETH_HEADER + IP_HEADER + ICMP_HEADER );

      usleep(1500);
      to_send = pck;
      to_send += Inet_Forge_ethernet(to_send, MyMAC, &MACHosts[i*6], ETH_P_IP);
      to_send += Inet_Forge_ip( to_send, SpoofIP, Hosts[i], ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP);
      icmp = (ICMP_header *) to_send;
      to_send += Inet_Forge_icmp( to_send, ICMP_ECHO, 0, NULL, 0);
      icmp->un.echo.seq = htons(i);
      icmp->un.echo.id = htons(0xD705);
      icmp->checksum = 0;
      icmp->checksum = Inet_Forge_ChecksumIP((u_short *)icmp, ICMP_HEADER);
      Inet_SendRawPacket(sock, pck, ETH_HEADER + IP_HEADER + ICMP_HEADER );
   }

   TIME_START;
   do
   {
       short pkttype;
       len = Inet_GetRawPacket(sock, pck, MTU, &pkttype);
       TIME_FINISH;

       if ( len > 0 && pkttype == PACKET_HOST )
       {
          eth = (ETH_header *) pck;
          if (eth->type == htons(ETH_P_IP))
          {
             ip = (IP_header *)(eth+1);
             if ( ip->proto == IPPROTO_ICMP && ip->dest_ip != MyIP)
             {
               icmp = (ICMP_header *) ((int)ip + ip->h_len * 4);
               if (icmp->type == ICMP_ECHOREPLY && (icmp->un.echo.id==htons(0x570D) || icmp->un.echo.id==htons(0xD705))   )
               {
                  if (icmp->un.echo.id==htons(0x570D))
                  {
                     ReceivedS[ntohs(icmp->un.echo.seq)]=1;
                     notrecv = 0;
                  }
                  if (icmp->un.echo.id==htons(0xD705))
                  {
                     ReceivedD[ntohs(icmp->un.echo.seq)]=1;
                     notrecv=0;
                  }
               }
             }
          }
       }
       else
         if (len <=0 )
            usleep(1500);
   } while(TIME_ELAPSED < 3);

   if (notrecv)
       Plugin_Output("\nNo poisoning at all :(\n");
   else
   {
       for (i=0; i<hnumb; i++)
       {
           struct in_addr addr1, addr2;
           if (!ReceivedD[i])
            {
                notrecv=1;
                addr1.s_addr = Hosts[i];
                addr2.s_addr = SpoofIP;
                Plugin_Output("\nNo poisoning between: %s",inet_ntoa(addr1));
                Plugin_Output(" -> %s\n", inet_ntoa(addr2));
            }

            if (!ReceivedS[i])
            {
                notrecv=1;
                addr1.s_addr = Hosts[i];
                addr2.s_addr = SpoofIP;
                Plugin_Output("\nNo poisoning between: %s",inet_ntoa(addr2));
                Plugin_Output(" -> %s\n", inet_ntoa(addr1));
            }
       }

       if (!notrecv)
           Plugin_Output("\nPoisoning process successful!!!\n");
   }

   Inet_Forge_packet_destroy( pck );
   free(Hosts);
   free(ReceivedS);
   free(ReceivedD);
   free(MACHosts);
   return 0;
}

/* EOF */
