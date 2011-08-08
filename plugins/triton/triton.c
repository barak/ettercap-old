/*
    triton -- ettercap plugin -- try to discover the gateway

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

    $Id: triton.c,v 1.4 2001/09/27 19:07:40 alor Exp $
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

#define NON_LOCAL_IP  "216.136.171.201"     // we need a good non local ip (ettercap.sourceforge.net)

// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int triton_function(void *dummy);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Try to discover the LAN's gateway",
   plug_version:     21,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &triton_function,
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

int triton_function(void *dummy)
{
   int sock, MTU, len=0, i;
   char c[2] = "";
   char *buf, *pck_to_send;
   u_long MyIP, NetMask;
   ETH_header *eth;
   IP_header  *ip;
   TCP_header *tcp;
   char MAC[20];
   char MyMAC[6];
   TIME_DECLARE;

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, MyMAC, &MyIP, &NetMask);

   buf = Inet_Forge_packet(MTU);
   fcntl(sock, F_SETFL, O_NONBLOCK);

   if (number_of_hosts_in_lan > 1)  // active scanning... host per host requst a non local ip.
   {

      Plugin_Output("\nActive searching of the gateway... (press return to stop)\n\n");

      for (i=1; i< number_of_hosts_in_lan; i++)
      {
         Plugin_Output("Trying %s...", Host_In_LAN[i].ip);

         Inet_GetMACfromString(Host_In_LAN[i].mac, MAC);

         pck_to_send = buf;
         pck_to_send += Inet_Forge_ethernet( pck_to_send, MyMAC, MAC, ETH_P_IP );
         pck_to_send += Inet_Forge_ip( pck_to_send, MyIP, inet_addr(NON_LOCAL_IP), TCP_HEADER, 0xe77e, 0, IPPROTO_TCP);
         pck_to_send += Inet_Forge_tcp( pck_to_send, 0xe77e, 80, 0, 0, TH_SYN, 0, 0);

         Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + TCP_HEADER );

         TIME_START;

         do
         {
            len = Inet_GetRawPacket(sock, buf, MTU, NULL);
            TIME_FINISH;

            if (Plugin_Input(c, 1, P_NONBLOCK))
            {
               Inet_Forge_packet_destroy( buf );
               Inet_CloseRawSock(sock);
               return 0;
            }

            if (len > 0)
            {
               eth = (ETH_header *) buf;
               if (eth->type == htons(ETH_P_IP))
               {
                  ip = (IP_header *)(eth+1);
                  if ( ip->proto == IPPROTO_TCP && ip->source_ip == inet_addr(NON_LOCAL_IP) )   // this is from the outer space... ;)
                  {
                     tcp = (TCP_header *) ((int)ip + ip->h_len * 4);
                     if ( (tcp->flags & (TH_SYN | TH_ACK)) || (tcp->flags & TH_RST))
                     {
                        if (memcmp(eth->source_mac, MAC, 6))
                        {
                           int j;
                           char GWMAC[6];
                           for (j=1; j<number_of_hosts_in_lan; j++)
                           {
                              Inet_GetMACfromString(Host_In_LAN[j].mac, GWMAC);
                              if (!memcmp(eth->source_mac, GWMAC, 6))
                                 Plugin_Output("\t this is host is forwarding IP packets to the real gateway %s...\n\n", Host_In_LAN[j].ip);
                           }
                        }
                        else
                           Plugin_Output("\t Found !! this is the gateway (%s)\n\n", Host_In_LAN[i].mac);

                        Inet_Forge_packet_destroy( buf );
                        Inet_CloseRawSock(sock);
                        return 0;
                     }
                  }
               }
            }
            else
               usleep(1500);

         } while(TIME_ELAPSED < 3);
         Plugin_Output("\t no replies within 3 sec !\n");
      }
      Inet_Forge_packet_destroy( buf );
      Inet_CloseRawSock(sock);
      return 0;
   }
   else  // we don't have the list... search in passive mode...
   {
      MyIP = MyIP & NetMask;

      Plugin_Output("\nPassive searching of the gateway... (press return to stop)\n\n");

      loop
      {
         len = Inet_GetRawPacket(sock, buf, MTU, NULL);

         if (len > 0)
         {
            eth = (ETH_header *) buf;
            if (eth->type == htons(ETH_P_IP))
            {
               ip = (IP_header *)(eth+1);
               if ( (ip->dest_ip & NetMask) != MyIP || (ip->source_ip & NetMask) != MyIP )   // this is from the outer space... ;)
               {
                  if ((ip->dest_ip & NetMask) != MyIP)
                     Inet_PutMACinString(MAC, eth->dest_mac);
                  else if ((ip->source_ip & NetMask) != MyIP)
                     Inet_PutMACinString(MAC, eth->source_mac);

                  Plugin_Output("Probably the gateway is %s\n", MAC);
               }
            }
         }
         else
             usleep(1000);

         if (Plugin_Input(c, 1, P_NONBLOCK))
         {
            Inet_Forge_packet_destroy( buf );
            Inet_CloseRawSock(sock);
            return 0;
         }
      }  // end loop

   }  // endif

}

/* EOF */
