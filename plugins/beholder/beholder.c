/*
    beholder -- ettercap plugin --  Find connections on a switched LAN

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
*/

#include <fcntl.h>
#include <unistd.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"


// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int beholder(void *dummy);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Find connections on a switched LAN",
   plug_version:     11,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &beholder,
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

int beholder(void *dummy)
{
   int MTU, sock;
   char *recv_pck;

   Plugin_Output("\nSupposed connections between... (press return to stop)\n\n");

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, 0, 0, 0);
   recv_pck = (char *)Inet_Forge_packet( MTU );
   fcntl(sock,F_SETFL,O_NONBLOCK);

   loop
   {
      char c[1] = "";
      int len;
      ARP_header *arp;
      ETH_header *eth;

      len = Inet_GetRawPacket(sock, recv_pck, MTU, NULL);

      if (len>0)
      {
         eth = (ETH_header *) recv_pck;
         if ( ntohs(eth->type) == ETH_P_ARP )
         {
            arp = (ARP_header *)(recv_pck + ETH_HEADER);
            if ( ntohs(arp->opcode) == ARPOP_REQUEST )
            {
               struct in_addr addr_source;
               struct in_addr addr_dest;
               char MAC[18];

               addr_dest.s_addr = *(int *)arp->dest_ip;
               addr_source.s_addr = *(int *)arp->source_ip;

               Inet_PutMACinString(MAC, arp->source_add);

               Plugin_Output("ARP REQUEST: [%s] %s ", MAC, inet_ntoa(addr_source));
               Plugin_Output("-> %s\n", inet_ntoa(addr_dest));
            }
         }
      }
      else
         usleep(2000);

      if (Plugin_Input(c, 1, P_NONBLOCK))
      {
         Inet_Forge_packet_destroy( recv_pck );
         Inet_CloseRawSock(sock);
         return 0;
      }
   }
}

/* EOF */
