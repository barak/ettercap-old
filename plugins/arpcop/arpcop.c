/*
    arpcop -- ettercap plugin -- report suspicious ARP activity

    Copyright (C) 2001  ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>

	 Copyright (C) 2001 for this plugin :  Paulo Madeira <acelent@hotmail.com>

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

    $Id: arpcop.c,v 1.4 2001/12/20 20:09:44 alor Exp $
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_inet.h"
#include "../../src/include/ec_inet_forge.h"
#include "../../src/include/ec_error.h"


typedef struct host_list_s host_list;

struct host_list_s {
   u_long IP_Add;
   u_char MAC_Add[6];
   host_list *next;
};

host_list *list;

char ETH_BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
char ARP_BROADCAST[6] = {0x0,0x0,0x0,0x0,0x0,0x0};

// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int arpcop_function(void *dummy);
int ip_aton(const char *ip_str);
host_list *arpcop_Host_in_LAN_list(void);
void arpcop_Free_list(host_list *head);
int Is_LAN_IP(int rem_ip);
void Parse_packet(char *buffer);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "Report suspicious ARP activity",
   plug_version:     10,
   plug_type:        PT_EXT,
   hook_point:       HOOK_NONE,
   hook_function:    &arpcop_function,
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


int ip_aton(const char *ip_str)
{
   int v[4], ip_int;
   sscanf(ip_str, "%d.%d.%d.%d", &v[0], &v[1], &v[2], &v[3]);
   ip_int = v[0] | (v[1] << 8) | (v[2] << 16) | (v[3] << 24);
   return ip_int;
}

host_list *arpcop_Host_in_LAN_list(void)
{
   HOST *host;
   host_list *head, **a_index;
   int i;

   head = NULL;
   a_index = &head;
   for (i=0, host=Host_In_LAN; i<number_of_hosts_in_lan; i++, host++)
   {
      if ( (*a_index = (host_list *) malloc(sizeof(host_list))) == NULL)
         Error_msg("arpcop:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
      (*a_index)->IP_Add = inet_addr(host->ip);
      Inet_GetMACfromString(host->mac, (*a_index)->MAC_Add);
      (*a_index)->next = NULL;
      a_index = &(*a_index)->next;
   }

   if (head == NULL)
   {
      if ( (head = (host_list *) malloc(sizeof(host_list))) == NULL)
         Error_msg("arpcop:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
      head->IP_Add = inet_addr(Inet_MyIPAddress());
      Inet_GetMACfromString(Inet_MyMACAddress(), head->MAC_Add);
      head->next = NULL;
   }

   if (head->next == NULL)
   {
      Plugin_Output("\nYou need a host list to get reliable information\n");
      Plugin_Output("Run ettercap without -z option or with -l\n");
   }
   return head;
}

void arpcop_Free_list(host_list *head)
{
   if (head == NULL) return;

   arpcop_Free_list(head->next);
   free(head);
}

int Is_LAN_IP(int rem_ip)
{
   int my_ip, mask;
   my_ip = inet_addr(Inet_MyIPAddress());
   mask = inet_addr(Inet_MySubnet());
   my_ip &= mask;
   rem_ip &= mask;
   return ( rem_ip == my_ip );
}

/* too big and slow, but it works... */
void Parse_packet(char *buffer)
{
   ARP_header *arp;
   ETH_header *eth;
   host_list **a_index;
   char IPS[16];
   char IPD[16];
   char MAC[18];
   char time_str[9];
   time_t time_v;

   time(&time_v);
   sscanf(ctime(&time_v), "%*s %*s %*s %8c", time_str);
   time_str[8] = 0;

   eth = (ETH_header *) buffer;

   if ( ntohs(eth->type) == ETH_P_ARP )
   {
      arp = (ARP_header *)(buffer + ETH_HEADER);

      if ( ntohs(arp->opcode) == ARPOP_REPLY )
      {
/*         Inet_PutMACinString(MAC, arp->source_add);
         Plugin_Output("\nARP reply: IP %s MAC %s ...\n", int_ntoa(arp->source_ip), mac_str);*/

         /* prevent from logging ourselves, by MAC, not by IP */
         /* so we can have a chance of catching someone sniffing us */
         /*    when someone is sniffing us with a good public arp sniffer */
         /*    there is no way to tell if we're being sniffed... */
         if ( memcmp(list->MAC_Add, arp->source_add, 6) == 0 ) return;

         a_index = &list;

         /* a_index will point to a know IP host_list node, otherwise will point to NULL */
         while (*a_index != NULL && memcmp(&((*a_index)->IP_Add), arp->source_ip, 4))
            a_index = &((*a_index)->next);

         /* if IP is new... */
         if (*a_index == NULL)
         {
            /* report it */
            Inet_PutMACinString(MAC, arp->source_add);
            strncpy(IPS, int_ntoa(arp->source_ip), 16);
            Plugin_Output("\n%s New IP %s found with MAC %s", time_str, IPS, MAC);

            /* See if it matches the subnet mask */
            if ( !Is_LAN_IP( *((int*)(arp->source_ip)) ) )
            {
               /* If not it's an ARP reply from outside! THAT DOESN'T HAPPEN!! */
               /* It would have to be a stupid gateway! It's wise to assume that */
               /* sniffing is going around here somewhere */
               /* I'm discarding the possibility of having a badly configured lan card */
               /*    there is no way to avoid logging ourserlves when we STOP sniffing */
               /*    but that's not bad because it's not our MAC on that packet */
               Plugin_Output("\nThis IP does not belong to the LAN!!\n");
               Plugin_Output("Bad card configuration OR MOST PROBABLY someone is sniffing");
            }
            else /* ARP reply is "normal", came from someone in the LAN */
            {
               /* check host_list to see if MAC is known */
               for (a_index = &list; *a_index != NULL; a_index = &((*a_index)->next))
                  /* if so we watched an IP change */
                  if ( memcmp((*a_index)->MAC_Add, arp->source_add, 6) == 0 &&
                       memcmp(&((*a_index)->IP_Add), arp->source_ip, 4) != 0 )
                  {
                     strncpy(IPD, int_ntoa((*a_index)->IP_Add), 16);
                     Plugin_Output("\nMAC %s originally reported as being IP %s\n", MAC, IPD);
                     Plugin_Output("IP change, old: %s  new: %s", IPD, IPS);
                     break;
                  }
               /* if MAC is unknown (new), a new card is on the LAN */
               if (*a_index == NULL)
               {
                  /* append a new node to the list */
                  if ( (*a_index = (host_list *)malloc(sizeof(host_list))) == NULL)
                     Error_msg("arpcop:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
                  (*a_index)->next = NULL;
               }
               /* update host_list node information */
               memcpy((*a_index)->MAC_Add, arp->source_add, 6);
               memcpy((char *)&((*a_index)->IP_Add), arp->source_ip, 4);
            }
            Plugin_Output(" ...\n");
         }
         /* IP is known */
         else
         {
            /* if that IP has a MAC different from the one reported in the current packet... */
            if (memcmp((*a_index)->MAC_Add, arp->source_add, 6))
            {
               /* report it */
               Inet_PutMACinString(MAC, arp->source_add);
               strncpy(IPS, int_ntoa(arp->source_ip), 16);
               Plugin_Output("\n%s ARP inconsistency: IP %s reports as being MAC %s\n", time_str, IPS, MAC);

               /* find the sucker-in-the-middle */
               a_index = &list;
               while (*a_index != NULL && memcmp((*a_index)->MAC_Add, arp->source_add, 6))
                  a_index = &((*a_index)->next);

               /* this lan card just got turned on, making conflit with an existing IP */
               /*    there is a possibility of advanced software/hardware to report an unknown MAC!! */
               /*    this could be a future option in ettercap, random MACs different from the existing ones */
               if (*a_index == NULL)
               {
                  Plugin_Output("This is a new MAC in the LAN\n");
                  Plugin_Output("IP conflit or MAC deviation (sniffing) ...\n");
               }
               /* there is the sucker */
               /*    on a lamers network it may be just a sucker making */
               /*    IP conflit to ruin the other lamer's connections */
               /*    if no lamers populate your network, it may be a sniff */
               else
               {
                  strcpy(IPD, int_ntoa((*a_index)->IP_Add));
                  Plugin_Output("MAC %s originally reported as being IP %s\n", MAC, IPD);
                  Plugin_Output("IP conflit or IP %s is being sniffed by IP %s ...\n", IPS, IPD);
               }
            }
         }
      }
   }
}


int arpcop_function(void *dummy)
{
    int sock, MTU = 1500;
    char *recv_pck;
    char c[2] = "";

    sock = Inet_OpenRawSock(Options.netiface);
    Inet_GetIfaceInfo(Options.netiface, &MTU, NULL, NULL, NULL);

    list = arpcop_Host_in_LAN_list();

    recv_pck = (u_char *)Inet_Forge_packet(MTU);

    Plugin_Output("\nWatching suspicious ARP replies (hit return to exit)...\n\n");

    fcntl(sock, F_SETFL, O_NONBLOCK);

    loop
    {
      int len = 0;

        len = Inet_GetRawPacket(sock, recv_pck, MTU, NULL);

        if (len > 0) Parse_packet(recv_pck);

        if (Plugin_Input(c, 1, P_NONBLOCK))
            break;

    }

    arpcop_Free_list(list);

    Inet_Forge_packet_destroy( recv_pck );
    Inet_CloseRawSock(sock);

    return 0;
}

/* EOF */
