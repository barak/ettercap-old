/*
    imp -- ettercap plugin -- Try to retrieve some Windows names

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

    $Id: imp.c,v 1.4 2001/09/27 19:07:40 alor Exp $
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
int imp_function(void *dummy);
void toggle( char *spacer);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Retrieves some Windows names",
   plug_version:     12,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &imp_function,
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

void toggle( char *spacer)
{
   int i;
   for(i=/*strlen(spacer)-1*/15;;i--)
      if(spacer[i-1]!=0x20)
      {
         spacer[i]=0;
         break;
      }
}

int imp_function(void *dummy)
{
   int sock, i, MTU, reply=0;
   char dgram[]="\x01\xF8\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20"
                 "\x43\x4B\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                 "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                 "\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01";
   char parser[4096], answers, *names, *buf;
   char MyMAC[6], DestMAC[6], MyIP[16];
   ETH_header  *HEther;
   IP_header *HIP;
   UDP_header *HUDP;
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

   Plugin_Output("\nTry to retrieve some Windows names from %s...\n", Host_Dest.ip);

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, NULL, NULL, NULL);
   Inet_GetMACfromString(Inet_MyMACAddress(), MyMAC);
   memcpy (DestMAC, Inet_MacFromIP(inet_addr(Host_Dest.ip)), 6);
   strncpy(MyIP,Inet_MyIPAddress(),16);

   buf = Inet_Forge_packet( ETH_HEADER + IP_HEADER + UDP_HEADER + sizeof(dgram) );
   Inet_Forge_ethernet( buf, MyMAC, DestMAC, ETH_P_IP );
   Inet_Forge_ip( buf + ETH_HEADER,
                  inet_addr(MyIP),
                  inet_addr(Host_Dest.ip),
                  UDP_HEADER + sizeof(dgram) - 1 ,
                  0xe77e, 0,
                  IPPROTO_UDP );
   Inet_Forge_udp ( buf + ETH_HEADER + IP_HEADER,
                    6969, 137,
                    dgram, sizeof(dgram) - 1);
   memcpy( buf + ETH_HEADER + IP_HEADER + UDP_HEADER , dgram, sizeof(dgram));
   Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + UDP_HEADER + sizeof(dgram) - 1);
   Inet_Forge_packet_destroy( buf );

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
            if (HIP->proto != IPPROTO_UDP) continue;
            if (HIP->source_ip != inet_addr(Host_Dest.ip)) continue;

            HUDP = (UDP_header *) ((int)HIP + HIP->h_len * 4);
            if (htons(HUDP->source)!=137 || htons(HUDP->dest)!=6969) continue;
            memcpy (parser, HUDP+1, htons(HUDP->len));

            reply++;
            break;
         }
      }
   } while (TIME_ELAPSED < 3);

   Inet_CloseRawSock(sock);

   if (!reply)
   {
      Plugin_Output("\nNo replies within 3 seconds!!! (host could be down)\n");
      Inet_Forge_packet_destroy(buf);
      return 0;
   }

   answers=parser[56];

   if (!answers)
   {
      Plugin_Output("No name in the answer....\n");
      Inet_Forge_packet_destroy(buf);
      return 0;
   }

   answers--;
   names=(char *)malloc(answers*20);

   Plugin_Output("Retrieved %d names:\n", answers);

   for (i=0; i<answers; i++)
   {
      int tries=0;
      char type;
      // TO DO: only names

       strncpy(&names[tries*20],&parser[57+i*18],15);
       type=parser[57+i*18+16];
       toggle(&names[tries*20]);

       if (type&0x80)
           Plugin_Output("%d) %s (Group)\n", i+1, &names[tries*20]);
       else
           Plugin_Output("%d) %s (Unique)\n", i+1, &names[tries*20]);

       tries++;
   }

   Inet_Forge_packet_destroy(buf);
   free(names);
   return 0;
}

/* EOF */
