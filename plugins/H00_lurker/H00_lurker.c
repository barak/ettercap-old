/*
    lurker -- ettercap plugin -- try to search for other ettercap

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

    $Id: H00_lurker.c,v 1.2 2002/02/10 10:07:00 alor Exp $
*/

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"

// protos....

int Plugin_Init(void *);
int Plugin_Fini(void *);
int lurker(void *buffer);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Try to search for other ettercaps",
   plug_version:     20,
   plug_type:        PT_HOOK,
   hook_point:       PCK_RECEIVED_RAW,
   hook_function:    &lurker,
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

int lurker(void *buffer)              // very lame searching...
{                                     // only for script-kiddes...
   IP_header  *ip;
   TCP_header *tcp;
   ETH_header *eth;
   char IPS[16];
   char IPD[16];
   RAW_PACKET *pck_raw;

   pck_raw = (RAW_PACKET *)buffer;

   eth = (ETH_header *) pck_raw->buffer;
   if ( ntohs(eth->type) == ETH_P_IP )
   {
      ip = (IP_header *)(eth+1);

      strcpy(IPS, inet_ntoa(*(struct in_addr *)&ip->source_ip) );
      strcpy(IPD, inet_ntoa(*(struct in_addr *)&ip->dest_ip) );

      if ( ntohs(ip->ident) == 0xe77e )
      {
         Plugin_Hook_Output("ettercap traces coming from %s ...\n", IPS );
      }

      if ( ntohs(ip->ident) == 0xbadc )
      {
         Plugin_Hook_Output("Banshee is killing from %s to %s ...\n", IPS, IPD );
      }

      if ( ip->proto == IPPROTO_TCP )
      {

         tcp = (TCP_header *) ((int)ip + ip->h_len * 4);

         switch( ntohl(tcp->seq) )
         {
            case 0xe77e:
               Plugin_Hook_Output("ettercap traces coming from %s ...\n", IPS );
               break;
            case 6969:
               Plugin_Hook_Output("%s is shadowing (scanning) %s ...\n", IPS, IPD );
               break;
            case 0xabadc0de:
               if ( ntohs(ip->ident) == 0xe77e && ntohl(tcp->ack_seq) == 0xabadc0de)
                  Plugin_Hook_Output("Spectre is flooding the LAN...\n");
               else
                  Plugin_Hook_Output("%s is golemizing %s ...\n", IPS, IPD );
               break;
         }
      }
   }

   return 0;
}


/* EOF */
