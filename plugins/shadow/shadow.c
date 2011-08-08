/*
    shadow -- ettercap plugin -- simple port scan

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

    $Id: shadow.c,v 1.3 2001/09/27 19:07:40 alor Exp $
*/

#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"
#include "../../src/include/ec_decodedata.h"

#define SYN_SEQ 6969

// global data...

int IPS, IPD, port_index=0;
int *PORTREP;

// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int shadow_main(void *dummy);
void Parse_packet(char *buffer);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "A very simple SYN/TCP port scanner",
   plug_version:     18,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &shadow_main,
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

void Parse_packet(char *buffer)
{
   IP_header  *ip;
   TCP_header *tcp;

   ip = (IP_header *) (buffer+ETH_HEADER);
   if (ip->source_ip==IPD && ip->dest_ip==IPS && ip->proto==IPPROTO_TCP)
   {
      tcp = (TCP_header *) ((int)ip + ip->h_len * 4);
      if ( (tcp->flags & TH_SYN) && (tcp->flags & TH_ACK) )
      {
         int i;
         for (i=0; i<port_index; i++)
             if (ntohs(tcp->source)==PORTREP[i]) break;

         if (i==port_index)
         {
            PORTREP[i]=ntohs(tcp->source);
            port_index++;
         }
      }
   }
}


int shadow_main(void *dummy)
{
    int i, sock, MTU, startP, finP, OldIndex=0;
    unsigned short PORTS, IP_ID;
    unsigned char MACS[6];
    unsigned char MACD[6];
    char numero[10];
    char *pck_to_send;
    TIME_DECLARE;

    if (!strcmp(Host_Dest.ip,""))
    {
      Plugin_Output("Please select a Dest...\n");
      return 0;
    }

    if (!strcmp(Host_Dest.ip, Inet_MyIPAddress()))
    {
       Plugin_Output("\nThis plugin doesn't work on myself !!\n");
       return 0;
    }

    Plugin_Output("\nStarting Port: ");
    Plugin_Input(numero, 10, P_BLOCK);
    startP = atoi(numero);

    Plugin_Output("Stopping Port: ");
    Plugin_Input(numero, 10, P_BLOCK);
    finP = atoi(numero);

    if (startP>finP)
    {
		Plugin_Output("\nStopping Port must be greater than Starting Port\n");
		return 0;
    }

    IPD = inet_addr(Host_Dest.ip);

    sock = Inet_OpenRawSock(Options.netiface);
    Inet_GetIfaceInfo(Options.netiface, &MTU, MACS, (unsigned long *)&IPS, 0);
    memcpy(MACD, Inet_MacFromIP(inet_addr(Host_Dest.ip)), 6);

    PORTREP = (int *)malloc((finP-startP+10)*sizeof(int));
    memset(PORTREP,0,(finP-startP+10)*sizeof(int));
    srand(time(0));
    IP_ID = PORTS = rand()%(0xFFFE)+1;

    pck_to_send = (char *)Inet_Forge_packet(MTU);

    Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_IP );
    Inet_Forge_ip( pck_to_send + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);

    for (i=startP; i<=finP; i++)
    {
       Inet_Forge_tcp( pck_to_send + ETH_HEADER + IP_HEADER, PORTS, i,  SYN_SEQ, 0, TH_SYN, 0, 0);
       Inet_SendRawPacket(sock, pck_to_send, ETH_HEADER + IP_HEADER + TCP_HEADER );
       if (!(i%5)) usleep(500);
    }

    Plugin_Output("\n\nScanning %s  %d -> %d ...\n\n",Host_Dest.ip, startP, finP);

    fcntl(sock, F_SETFL, O_NONBLOCK);

    TIME_START;

    do
    {
        Inet_GetRawPacket(sock, pck_to_send, MTU, NULL);
        Parse_packet(pck_to_send);

        TIME_FINISH;

        for (;OldIndex<port_index; OldIndex++)
        {
          char *desc;
          desc = strdup(Decodedata_GetType('T', PORTREP[OldIndex], PORTREP[OldIndex]));
          Plugin_Output("Open Port: %4d/tcp %s\n", PORTREP[OldIndex], desc);
        }

    } while (TIME_ELAPSED < 2);

    Inet_Forge_packet_destroy( pck_to_send );
    free(PORTREP);
    Inet_CloseRawSock(sock);
    return 0;
}

/* EOF */
