/*
    ooze -- ettercap plugin -- ping a host

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

    $Id: ooze.c,v 1.3 2001/09/27 19:07:40 alor Exp $
*/


#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"

// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int ooze_function(void *dummy);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Ping a host",
   plug_version:     14,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &ooze_function,
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

int ooze_function(void *dummy)
{
   char *buf;
   int sock, MTU, i, reply=0;
   char MyMAC[6], DestMAC[6];
   char MyIP[16];
   ETH_header  *HEther;
   IP_header *HIP;
   char numero[5];
   int num;
   TIME_DECLARE;

   if (!strcmp(Host_Dest.ip, ""))
   {
      Plugin_Output("\nNo destination host selected !!\n");
      return 0;
   }

   if (!strcmp(Host_Dest.ip, Inet_MyIPAddress()))
   {
      Plugin_Output("\nThis plugin doesn't work on myself !!\n");
      return 0;
   }

   Plugin_Output("\nHow many ping ? ");
   Plugin_Input(numero, 5, P_BLOCK);

   num = atoi(numero);

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, NULL, NULL, NULL);

   Inet_GetMACfromString(Inet_MyMACAddress(), MyMAC);

   memcpy (DestMAC, Inet_MacFromIP(inet_addr(Host_Dest.ip)), 6);

   strncpy(MyIP,Inet_MyIPAddress(),16);

   buf = Inet_Forge_packet( ETH_HEADER + IP_HEADER + ICMP_HEADER );

   for (i=0; i<num; i++)
   {
         Inet_Forge_ethernet( buf, MyMAC, DestMAC, ETH_P_IP );

         Inet_Forge_ip( buf + ETH_HEADER,
                        inet_addr(MyIP),
                        inet_addr(Host_Dest.ip),
                        sizeof(ICMP_header),
                        0xe77e,
                        0,
                        IPPROTO_ICMP );

         Inet_Forge_icmp( buf + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );



         Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + ICMP_HEADER);
         usleep(1000);
   }


   Inet_Forge_packet_destroy( buf );

   Plugin_Output("\n%d ICMP echo requests sent to %s. waiting for replies...\n\n", num, Host_Dest.ip);

   buf = Inet_Forge_packet( MTU );

   fcntl(sock, F_SETFL, O_NONBLOCK);

   TIME_START;

   do
   {
      short pkttype, len;

      len = Inet_GetRawPacket(sock, buf, MTU, &pkttype);

      TIME_FINISH;

      if (len > 0 && pkttype == PACKET_HOST)
      {

         HEther = (ETH_header *) buf;
         if ( ntohs(HEther->type) == ETH_P_IP )
         {

            HIP = (IP_header *)(HEther + 1);

            if (HIP->proto != IPPROTO_ICMP) continue;

            if (HIP->source_ip != inet_addr(Host_Dest.ip)) continue;

            reply++;
            Plugin_Output(" ICMP reply num %2d from %s after %.5f seconds\n", reply, Host_Dest.ip, TIME_ELAPSED );
         }
      }
   } while ( (TIME_ELAPSED < 3) && (reply < num) );

   if (!reply) Plugin_Output("\nNo replies within 3 seconds !! (host could be down)\n");

   Inet_CloseRawSock(sock);

   return 0;
}

/* EOF */
