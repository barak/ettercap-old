/*
    ettercap -- inet utilities, arp ping and more...

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

    $Id: ec_inet.c,v 1.17 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#ifdef CYGWIN
   #define _SYS_TIME_H_    // windows voodoo  (C) Gigi Sullivan
#endif
#include <sys/wait.h>
#ifdef CYGWIN
   #undef _SYS_TIME_H_
#endif

#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>


#ifndef WAIT_ANY
   #define WAIT_ANY       (-1)    /* Any process.  */
#endif

#include "include/ec_error.h"
#include "include/ec_inet_structures.h"
#include "include/ec_inet_forge.h"
#include "include/ec_buffer.h"
#include "include/ec_thread.h"
#include "include/ec_parser.h"

static char ETH_BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static char ARP_BROADCAST[6] = {0x0,0x0,0x0,0x0,0x0,0x0};

typedef struct {
   u_long IP_Add;
   u_char MAC_Add[6];
   struct host_list *next;
} host_list;

#ifdef LINUX
   struct ifreq old_ifr;      // old iface flags
   char IpForward_status;     // old ipforward status
#else
   int IpForward_status;      // old ipforward status
#endif

#ifdef CYGWIN
typedef struct sh {
   SOCKET fd;
   struct sockaddr_in sin;
} socket_handle;
#else
typedef int socket_handle;
#endif

// protos...

char * Inet_HostName(char *ip);
char * Inet_NameToIp(char *name);
char * Inet_GetMyInfo(char tipo);
char * Inet_MyIPAddress(void);
char * Inet_MyMACAddress(void);
char * Inet_MySubnet(void);
int Inet_HostInLAN(void);
void Inet_Free_list(host_list *head);
host_list *Inet_Host_in_LAN_list(char *iface);
SniffingHost *Inet_NoSniff(void);
void Inet_PutMACinString(char *mac_string, unsigned char *MAC);
int Inet_GetMACfromString(char *mac_string, unsigned char *MAC);
int Inet_Fake_Host(void);
int Inet_CheckSwitch(void);
int Inet_SendLargeTCPPacket(int sock, char *buffer, int len, int MTU);
int Inet_Load_Host_List(void);
char * Inet_Save_Host_List(void);

socket_handle Inet_OpenSocket(char *host, short port);
int Inet_CloseSocket(socket_handle sh);
int Inet_Http_Send(socket_handle sh, char *payload);
int Inet_Http_Receive(socket_handle sh, char *payload, size_t size);


// Following are architecture dependent !! implementations are in ./src/`uname`/ec_inet_`uname`.c
int Inet_FindIFace(char *iface);
int Inet_CorrectIface(char *iface);
int Inet_GetIfaceInfo(char *iface, int *MTU, char *MyMAC, u_long *IP, u_long *NetMask);
int Inet_SetPromisc(char *iface);
int Inet_OpenRawSock(char *iface);
void Inet_CloseRawSock(int sock);
int Inet_GetRawPacket(int sock, char *buffer, int MTU, short *type);
int Inet_SendRawPacket(int sock, char *buffer, int len);
void Inet_Restore_ifr(void);
void Inet_DisableForwarding(void);
void Inet_RestoreForwarding(void);
char *Inet_MacFromIP(unsigned long ip);
#ifdef PERMIT_HTTPS
   void Inet_UnSetARPEntry(void);
   int Inet_SetARPEntry(unsigned long IP, char MAC[6]);
   void Inet_UnsetRoute(void);
   void Inet_SetRoute(void);
#endif
// ----------------------------------------

// Architecture dependent implemetation of Inet functions...

#ifdef LINUX
   #include "OS/linux/ec_inet_linux.c"
#endif
#if defined (FREEBSD) || defined (OPENBSD) || defined (NETBSD)
   #include "OS/BSD/ec_inet_BSD.c"
#endif
#ifdef MACOSX
   #include "OS/MacOsX/ec_inet_macosx.c"
#endif
#ifdef SOLARIS
   #include "OS/solaris/ec_inet_solaris.c"
#endif
#ifdef CYGWIN
   #include "OS/windows/ec_inet_cygwin.c"
#endif

// ----------------------------------------


char * Inet_HostName(char *ip)   // returns hostname from ip
{
   struct hostent *host;
   static struct in_addr addr;

   if (!Options.dontresolve)
   {
      addr.s_addr = inet_addr(ip);
      host = gethostbyaddr((char *)&addr, sizeof(struct in_addr), AF_INET);
      #ifdef DEBUG
         if (host != NULL) Debug_msg("Inet_HostName -- [%s] [%s]", ip, (char *) host->h_name);
         else Debug_msg("Inet_HostName -- [%s] [NOT resolved...]", ip);
      #endif
      if (host != NULL) return (char *) host->h_name;
   }
   else
      return "not resolved (-d option)";

   return "Unknown host";
}


char * Inet_NameToIp(char *name) // returns ip from hostname
{
   struct hostent *host;
   struct in_addr addr;
   static char ip[16];

   memset(ip, 0, sizeof(ip));

   if ((addr.s_addr = inet_addr(name)) == -1) {
      host = gethostbyname(name);

      if (host != NULL) {
         strlcpy(ip, inet_ntoa( *(struct in_addr *) *host->h_addr_list), 16);
         return ip;
      }
      else
         Error_msg("Invalid host address %s !!", name);
   }

   strlcpy(ip, inet_ntoa( addr ), 16);

   return ip;
}


char * Inet_GetMyInfo(char tipo)
{
   u_long IP_Add, NetMask;
   unsigned char MAC_Add[6];
   static char MAC[18];
   static char MySubnet[16];
   static char IP[16];

   Inet_GetIfaceInfo(Options.netiface, NULL, MAC_Add, &IP_Add, &NetMask);

   switch (tipo)
   {
         case 0:  // requesting IP
                  snprintf(IP, sizeof(IP), "%s", int_ntoa(IP_Add));
                  #ifdef DEBUG
                     Debug_msg("Inet_GetMyInfo IP -- [%s]", IP);
                  #endif
                  return IP;
                  break;

         case 1:  // requesting MAC
                  Inet_PutMACinString( MAC, MAC_Add );
                  #ifdef DEBUG
                     Debug_msg("Inet_GetMyInfo MAC -- [%s]", MAC);
                  #endif
                  return MAC;
                  break;

         case 2:  // requesting netmask
                  snprintf(MySubnet, sizeof(MySubnet), "%s", int_ntoa(NetMask));
                  #ifdef DEBUG
                     Debug_msg("Inet_GetMyInfo NetMask -- [%s]", MySubnet);
                  #endif
                  return MySubnet;
                  break;
   }

   return "(none)";

}



char * Inet_MyIPAddress(void)
{
   return Inet_GetMyInfo(0);
}



char * Inet_MyMACAddress(void)
{
   return Inet_GetMyInfo(1);
}



char * Inet_MySubnet(void)
{
   return Inet_GetMyInfo(2);
}


int Inet_HostInLAN()
{
   host_list *list;
   host_list *current;
   int host_alive = 0, k = 0;

   if (Options.hostsfromfile)
       return Inet_Load_Host_List();

#ifdef DEBUG
   Debug_msg("Inet_HostInLAN\tIface: %s", Options.netiface);
#endif

   list = Inet_Host_in_LAN_list(Options.netiface);

   current = list;

   for( ; current; host_alive++)
      current = (host_list *)current->next;

   if (!Options.dontresolve && !Host_In_LAN)
      fprintf(stdout, "Resolving %d hostnames...\n", host_alive);

   if (Host_In_LAN) free(Host_In_LAN);
   Host_In_LAN = (HOST *)calloc(host_alive,sizeof(HOST));
   if (Host_In_LAN == NULL)
      ERROR_MSG("calloc()");

   current = list;
   for( ; current; current = (host_list *)current->next)
   {
      snprintf(Host_In_LAN[k].ip, sizeof(Host_In_LAN[k].ip), "%s", int_ntoa(current->IP_Add));
      snprintf(Host_In_LAN[k].name, 128, "%s", Inet_HostName(Host_In_LAN[k].ip));
      Inet_PutMACinString(Host_In_LAN[k].mac, current->MAC_Add);
      k++;
   }
   Inet_Free_list(list);
#ifdef DEBUG
   Debug_msg("Inet_HostInLAN -- %d hosts in the lan", host_alive);
#endif
   return host_alive;
}


char * Inet_Save_Host_List(void)
{
   FILE *hfile;
   u_long N_IP, N_MASK, index;
   static char hfile_name[50];
   char temp[50];
   struct in_addr ip_addr;
   struct in_addr mask_addr;

   Inet_GetIfaceInfo(Options.netiface, NULL, NULL, &N_IP, &N_MASK);

   N_IP = N_IP & N_MASK;
   ip_addr.s_addr = N_IP;
   mask_addr.s_addr = N_MASK;
   snprintf(temp, 49, "%s", inet_ntoa(mask_addr));
   snprintf(hfile_name, 49, "%s_%s.ehl", inet_ntoa(ip_addr), temp);

#ifdef DEBUG
   Debug_msg("Inet_Save_Host_List saving file: %s", hfile_name);
#endif

   hfile = fopen(hfile_name, "w");
   if (hfile == NULL)
      ERROR_MSG("fopen()");

   for (index = 1; index<number_of_hosts_in_lan; index++)
      fprintf(hfile,"%s %s %s\n",Host_In_LAN[index].ip, Host_In_LAN[index].mac, Parser_StrSpacetoUnder(Host_In_LAN[index].name));

   fclose(hfile);

   return hfile_name;
}



int Inet_Load_Host_List(void)
{
   FILE *hfile;
   char C_IP[50], C_MAC[50], C_NAME[128];
   char N_MAC[6];
   u_long N_IP;
   int  host_alive,index;

#ifdef DEBUG
   Debug_msg("Inet_Load_Host_List from file: %s", Options.hostfile);
#endif

   hfile = fopen(Options.hostfile,"r");
   if (hfile == NULL)
      ERROR_MSG("fopen()");

   fprintf(stdout, "Loading Host List from file %s\n", Options.hostfile);

   for (host_alive = 1; !feof(hfile); host_alive++)
      fscanf(hfile,"%49s %49s %127s\n", C_IP, C_MAC, C_NAME);
   fseek(hfile, 0, SEEK_SET);

#ifdef DEBUG
   Debug_msg("Inet_Load_Host_List -- %d hosts in the lan", host_alive);
#endif

   if (Host_In_LAN) free(Host_In_LAN);

   Host_In_LAN = (HOST *)calloc(host_alive,sizeof(HOST));
   if (Host_In_LAN == NULL)
      ERROR_MSG("calloc()");

   Inet_GetIfaceInfo(Options.netiface, NULL, N_MAC, &N_IP, NULL);

   snprintf(Host_In_LAN[0].ip, sizeof(Host_In_LAN[0].ip), "%s", int_ntoa(N_IP));
   Inet_PutMACinString(Host_In_LAN[0].mac, N_MAC);
   snprintf(Host_In_LAN[0].name, 128, "%s", Inet_HostName(Host_In_LAN[0].ip));

   for (index=1; index<host_alive; index++)
   {
      fscanf(hfile,"%49s %49s %127s\n", C_IP, C_MAC, C_NAME);
      snprintf(Host_In_LAN[index].ip, sizeof(Host_In_LAN[index].ip), "%s", C_IP);
      snprintf(Host_In_LAN[index].mac, sizeof(Host_In_LAN[index].mac), "%s", C_MAC);
      snprintf(Host_In_LAN[index].name, 128, "%s", C_NAME);
   }

   fclose(hfile);

   Options.hostsfromfile = 0;

   return host_alive;
}



void Inet_Free_list(host_list *head)
{
   if (!head) return;

   Inet_Free_list((host_list *) head->next);
   free(head);
}



host_list *Inet_Host_in_LAN_list(char *iface)
{
   int sock, N_hosts, i, MTU;
   u_long NetMask, BroadAdd, IP_to_use;
   host_list *head;
   u_char *buf;
   TIME_DECLARE;


#ifdef DEBUG
   Debug_msg("Inet_HostInLAN_list");
#endif

   head = (host_list *)malloc(sizeof(host_list));
   if (head == NULL)
      ERROR_MSG("malloc()");

   head->next = NULL;

   sock = Inet_OpenRawSock(iface);

   Inet_GetIfaceInfo(iface, &MTU, head->MAC_Add, &head->IP_Add, &NetMask);

   if (Options.silent)
   {
      Inet_CloseRawSock(sock);
      return head;
   }

   N_hosts = ntohl(~NetMask);

#ifdef DEBUG
   Debug_msg("Inet_HostInLAN_list -- netmask 0x%0x  hosts %d", htonl(NetMask), N_hosts);
#endif

   if (Options.broadping)
   {

      BroadAdd = head->IP_Add | (~NetMask);

      if (!Host_In_LAN)
         fprintf(stdout, "Sending broadcast ping to %s...\n", int_ntoa(BroadAdd));


      buf = Inet_Forge_packet( ETH_HEADER + IP_HEADER + ICMP_HEADER );
      Inet_Forge_ethernet( buf, head->MAC_Add, ETH_BROADCAST, ETH_P_IP );

      Inet_Forge_ip( buf + ETH_HEADER,
                     head->IP_Add,
                     BroadAdd,
                     sizeof(ICMP_header),
                     0xe77e,
                     0,
                     IPPROTO_ICMP );

      Inet_Forge_icmp( buf + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
      Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + ICMP_HEADER);
      Inet_Forge_packet_destroy( buf );

   }
   else // !broadping
   {

      if (!Host_In_LAN && Options.spoofIp)
         fprintf(stdout, "Spoofing source IP with %s...\n", int_ntoa(Options.spoofIp));

      if (!Host_In_LAN && Options.storm_delay != DEFAULT_STORM_DELAY)
         fprintf(stdout, "Interval between arp request is %.5f sec...\n", Options.storm_delay/1.0e6);

      if (!Host_In_LAN && host_to_be_scanned == 0)
         fprintf(stdout, "Sending %d ARP request...\n", N_hosts);
      else if (!Host_In_LAN && host_to_be_scanned > 0)
         fprintf(stdout, "Sending %d ARP request...\n", host_to_be_scanned);


      if (!fork())
      {
         buf = Inet_Forge_packet( ETH_HEADER + ARP_HEADER );

         // frame ethernet header
         Inet_Forge_ethernet( buf, head->MAC_Add, ETH_BROADCAST, ETH_P_ARP );

         if (Options.spoofIp)
            IP_to_use = Options.spoofIp;
         else
            IP_to_use = head->IP_Add;

         if (host_to_be_scanned > 0)   // only the hosts in the list
         {
            for (i=0; i<host_to_be_scanned; i++)
            {
               int dest_ip;
               dest_ip = inet_addr(Host_List[i]);
               Inet_Forge_arp( buf+ETH_HEADER, ARPOP_REQUEST,
                                  head->MAC_Add, IP_to_use,
                                  ARP_BROADCAST, dest_ip );

               usleep(Options.storm_delay);
               Inet_SendRawPacket(sock, buf, ETH_HEADER + ARP_HEADER);
            }
         }
         else  // all host in the subnet
         {
            for (i=1; i<=N_hosts; i++)
            {
               int dest_ip;
               dest_ip = (head->IP_Add&NetMask)|htonl(i);

               // if dest is equal to me
               if (dest_ip != head->IP_Add)
               {
                  // arp request
                  Inet_Forge_arp( buf+ETH_HEADER, ARPOP_REQUEST,
                                  head->MAC_Add, IP_to_use,
                                  ARP_BROADCAST, dest_ip );

                  usleep(Options.storm_delay);
                  Inet_SendRawPacket(sock, buf, ETH_HEADER + ARP_HEADER);
               }
            }
         }

         Inet_Forge_packet_destroy( buf );
         usleep(500000);   // 0.5 second to wait for slower replies (ettercap is syncronized on this process)
         exit(0);          // the forked process must exit after arp storm
      }
   }

#ifdef DEBUG
   Debug_msg("Inet_HostInLAN_list -- listening for replies...");
#endif

   if (!Host_In_LAN)
      fprintf(stdout, "Listening for replies...\n");

   fcntl(sock, F_SETFL, O_NONBLOCK);

   TIME_START;

   buf = Inet_Forge_packet( MTU );

   if (Options.broadping)
   {
         do
         {
            short pkttype;
            int len;
            host_list **current;
            ETH_header *HEther;
            IP_header *HIP;

            TIME_FINISH;

            len = Inet_GetRawPacket(sock, buf, MTU, &pkttype);

            if (len > 0 && pkttype == PACKET_HOST)
            {
               HEther = (ETH_header *) buf;
               if ( ntohs(HEther->type) == ETH_P_IP )
               {
                  HIP = (IP_header *)(HEther + 1);
                  if (HIP->proto != IPPROTO_ICMP) continue;
                  current = &head;

                  #ifdef DEBUG
                     Debug_msg("Inet_HostInLAN_list -- got a reply after %.5f seconds", TIME_ELAPSED );
                  #endif

                  while(*current != NULL && memcmp(&((*current)->IP_Add),&HIP->source_ip,4))
                     current = (host_list **)&((*current)->next);

                  if (*current == NULL)
                  {
                     if ( (*current = (host_list *)malloc(sizeof(host_list))) == NULL)
                         ERROR_MSG("malloc()");
                     (*current)->next = NULL;
                     memcpy((*current)->MAC_Add, HEther->source_mac, 6);
                     memcpy((char *)&((*current)->IP_Add), &HIP->source_ip, 4);
                  }
               }
            }
         } while ( TIME_ELAPSED < 2 );

   }
   else  // !broadping
   {

         do
         {
            int leng = 0;
            short pkttype;
            host_list **current;
            ETH_header *ethpkt;
            ARP_header *arppkt;

            leng = Inet_GetRawPacket(sock, buf, MTU, &pkttype);

            ethpkt = (ETH_header *)buf;
            arppkt = (ARP_header *)(buf + ETH_HEADER);

            TIME_FINISH;

            if (leng > 0 && pkttype == PACKET_HOST && ethpkt->type == htons(ETH_P_ARP) && arppkt->opcode == htons(ARPOP_REPLY))
            {
               current = &head;

               #ifdef DEBUG
                  Debug_msg("Inet_HostInLAN_list -- got a reply after %.5f seconds", TIME_ELAPSED );
               #endif

               while(*current != NULL && memcmp(&((*current)->IP_Add),arppkt->source_ip,4))
                  current = (host_list **)&((*current)->next);

               if (*current == NULL)
               {
                  if ( (*current = (host_list *)malloc(sizeof(host_list))) == NULL)
                     ERROR_MSG("malloc()");
                  (*current)->next = NULL;
                  memcpy((*current)->MAC_Add, arppkt->source_add, 6);
                  memcpy((char *)&((*current)->IP_Add), arppkt->source_ip, 4);
               }
            }
         } while ( waitpid(WAIT_ANY, NULL, WNOHANG) == 0 );

   }

   #ifdef DEBUG
      Debug_msg("Inet_HostInLAN_list -- waiting timed out after %.5f seconds", TIME_ELAPSED );
   #endif

   Inet_Forge_packet_destroy( buf );
   Inet_CloseRawSock(sock);
   return head;
}


SniffingHost *Inet_NoSniff(void)
{
   static SniffingHost *SniffTable=NULL;
   int i, j, len, sock, MTU, SniffTableIndex=0;
   ETH_header  *HEther;
   IP_header *HIP;
   u_char *buf;
   TIME_DECLARE;

#ifdef DEBUG
   Debug_msg("Inet_NoSniff");
#endif

   SniffTable = calloc(number_of_hosts_in_lan * 100, sizeof(SniffingHost));
   memset(SniffTable, 0, sizeof(SniffingHost)*number_of_hosts_in_lan);

   sock = Inet_OpenRawSock(Options.netiface);

   Inet_GetIfaceInfo(Options.netiface, &MTU, NULL, NULL, NULL);

   buf = Inet_Forge_packet( ETH_HEADER + IP_HEADER + ICMP_HEADER );

   for (i=0; i<number_of_hosts_in_lan; i++)
   {
      if (inet_addr(Host_In_LAN[0].ip) != inet_addr(Host_In_LAN[i].ip))
      {
         char MyMAC[6];
         char DestMAC[6];

         Inet_GetMACfromString(Host_In_LAN[0].mac, MyMAC);
         Inet_GetMACfromString(Host_In_LAN[i].mac, DestMAC);

         Inet_Forge_ethernet( buf, MyMAC, DestMAC, ETH_P_IP );

         Inet_Forge_ip( buf + ETH_HEADER,
                        inet_addr(Host_In_LAN[0].ip),
                        inet_addr(Host_In_LAN[i].ip),
                        sizeof(ICMP_header),
                        0xe77e,
                        0,
                        IPPROTO_ICMP );

         Inet_Forge_icmp( buf + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );

         Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + ICMP_HEADER);
         usleep(1000);
      }
   }

   Inet_Forge_packet_destroy( buf );

#ifdef DEBUG
   Debug_msg("Inet_NoSniff -- after ICMP storm");
#endif

   buf = Inet_Forge_packet( MTU );

   fcntl(sock, F_SETFL, O_NONBLOCK);

   TIME_START;

   // Search for strange replies
   do
   {
      short pkttype;

      TIME_FINISH;

      len = Inet_GetRawPacket(sock, buf, MTU, &pkttype);

      if (len > 0 && pkttype == PACKET_HOST)
      {
         HEther = (ETH_header *) buf;
         if ( ntohs(HEther->type) == ETH_P_IP )
         {
            unsigned char MACS[20];
            HIP = (IP_header *)(HEther + 1);
            Inet_PutMACinString(MACS, HEther->source_mac);

            if (HIP->proto != IPPROTO_ICMP) continue;

#ifdef DEBUG
   Debug_msg("Inet_NoSniff -- got a ICMP reply after %.5f seconds", TIME_ELAPSED );
#endif

            for(i=0; i<number_of_hosts_in_lan; i++)
            {
               if ( inet_addr(Host_In_LAN[i].ip ) == HIP->source_ip )
               {
                  if (memcmp(MACS,Host_In_LAN[i].mac,17))
                  {
                     for (j=0; j<number_of_hosts_in_lan; j++)
                        if (!memcmp(MACS, Host_In_LAN[j].mac, 17)) break;

                     SniffTable[SniffTableIndex].Host_Index1=j;
                     SniffTable[SniffTableIndex].Host_Index2=i;
                     SniffTable[SniffTableIndex].mode=1;
                     SniffTableIndex++;
                     break;
                  }
               }
            }
         }
      }
   } while ( TIME_ELAPSED < 3 );

#ifdef DEBUG
   Debug_msg("Inet_NoSniff -- analyzing results" );
#endif

   // Search for strange ARP entries
   for (i=0; i<number_of_hosts_in_lan-1; i++)
      for(j=i+1; j<number_of_hosts_in_lan; j++)
         if (!memcmp(Host_In_LAN[i].mac, Host_In_LAN[j].mac, 17))
         {
            SniffTable[SniffTableIndex].Host_Index1=i;
            SniffTable[SniffTableIndex].Host_Index2=j;
            SniffTable[SniffTableIndex].mode=2;
            SniffTableIndex++;
         }

#ifdef DEBUG
   Debug_msg("Inet_NoSniff -- freeing buffer" );
#endif

   Inet_Forge_packet_destroy( buf );

   Inet_CloseRawSock(sock);
   return (SniffTable);
}


int Inet_Fake_Host(void)
{
   unsigned int N_hosts, i, j=0, k, base_ip, fake_ip=0;
   unsigned long NetMask;

   Inet_GetIfaceInfo(Options.netiface, NULL, NULL, NULL, &NetMask);
   N_hosts = ntohl(~NetMask);

   base_ip = inet_addr(Host_In_LAN[0].ip)&NetMask;

   for (i=1; i<N_hosts; i++)
   {
      fake_ip = base_ip|htonl(i);
      for (k=0; k < number_of_hosts_in_lan; k++)
         if (fake_ip == inet_addr(Host_In_LAN[k].ip)
            || fake_ip == inet_addr(Host_Source.ip)
            || fake_ip == inet_addr(Host_Dest.ip) )
            break;
      if (k == number_of_hosts_in_lan) break;
   }

   if (j == N_hosts) return 0;

   return (fake_ip);
}


// 0 - Unknown
// 1 - Hub
// 2 - Switch
int Inet_CheckSwitch()
{
   int link_type=2;

#ifdef DEBUG
   Debug_msg("Inet_CheckSwitch" );
#endif


   if (Options.link) return 0;

   if (number_of_hosts_in_lan==2)
   {
       int fakeip,destip,sock,MTU,i;
       char MyMAC[6],DestMAC[6];
       char *buf;
       TIME_DECLARE;

       fakeip=Inet_Fake_Host();
       destip=inet_addr(Host_In_LAN[1].ip);
       Inet_GetMACfromString(Host_In_LAN[1].mac, DestMAC);
       sock = Inet_OpenRawSock(Options.netiface);
       fcntl(sock, F_SETFL, O_NONBLOCK);
       Inet_GetIfaceInfo(Options.netiface, &MTU, MyMAC, NULL, NULL);
       Inet_SetPromisc(Options.netiface);

       buf = Inet_Forge_packet(MTU);
       Inet_Forge_ethernet( buf, MyMAC, DestMAC, ETH_P_IP );
       Inet_Forge_ip( buf + ETH_HEADER,
                      fakeip, destip,
                      sizeof(ICMP_header),
                      0xe77e, 0,
                      IPPROTO_ICMP );
       Inet_Forge_icmp( buf + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
       Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + ICMP_HEADER);

       Inet_Forge_ethernet( buf, MyMAC, DestMAC, ETH_P_ARP );
       Inet_Forge_arp( buf+ETH_HEADER, ARPOP_REPLY,
                       DestMAC, fakeip,
                       DestMAC, destip );
       for(i=0; i<5; i++)
       {
           usleep(1000);
           Inet_SendRawPacket(sock, buf, ETH_HEADER + ARP_HEADER);
       }

       TIME_START;
       do
       {
           short type; int len;

           len=Inet_GetRawPacket(sock,buf,MTU,&type);
           TIME_FINISH;

            if (len>0)
            {
               ETH_header *eth;
               eth=(ETH_header *)buf;
               if (!memcmp(DestMAC,eth->dest_mac,6))
               {
                  link_type=1;
                  break;
               }
            }
         }while(TIME_ELAPSED<1);

       free(buf);
       Inet_CloseRawSock(sock);
       Inet_Restore_ifr();
   }
   else
   if (number_of_hosts_in_lan>2)
   {
       int  sourceip,destip,sock,MTU;
       char MyMAC[6],DestMAC[6],SourceMAC[6];
       char *buf;
       TIME_DECLARE;

       sourceip=inet_addr(Host_In_LAN[2].ip);
       destip=inet_addr(Host_In_LAN[1].ip);
       Inet_GetMACfromString(Host_In_LAN[2].mac, SourceMAC);
       Inet_GetMACfromString(Host_In_LAN[1].mac, DestMAC);
       sock = Inet_OpenRawSock(Options.netiface);
       fcntl(sock, F_SETFL, O_NONBLOCK);
       Inet_GetIfaceInfo(Options.netiface, &MTU, MyMAC, NULL, NULL);
       Inet_SetPromisc(Options.netiface);

       buf = Inet_Forge_packet(MTU);
       Inet_Forge_ethernet( buf, MyMAC, DestMAC, ETH_P_IP );
       Inet_Forge_ip( buf + ETH_HEADER,
                      sourceip, destip,
                      sizeof(ICMP_header),
                      0xe77e, 0,
                      IPPROTO_ICMP );
       Inet_Forge_icmp( buf + ETH_HEADER + IP_HEADER, ICMP_ECHO, 0, NULL, 0 );
       Inet_SendRawPacket(sock, buf, ETH_HEADER + IP_HEADER + ICMP_HEADER);

       TIME_START;
       do
       {
           short type; int len;

           len=Inet_GetRawPacket(sock,buf,MTU,&type);
           TIME_FINISH;

            if (len>0)
            {
               ETH_header *eth;
               eth=(ETH_header *)buf;
               if (!memcmp(SourceMAC,eth->dest_mac,6))
               {
                  link_type=1;
                  break;
               }
            }
         }while(TIME_ELAPSED<1);

       free(buf);
       Inet_CloseRawSock(sock);
       Inet_Restore_ifr();
   }
   else return 0;


#ifdef DEBUG
   Debug_msg("Inet_CheckSwitch -- type %d", link_type );
#endif

   return link_type;
}



int Inet_GetMACfromString(char *mac_string, unsigned char *MAC)
{
   unsigned int MAC_Add[6];
   int i = 0;

   memset(&MAC_Add, 0, 6);

   if (!strcmp(mac_string, "")) memset(MAC, 0, 6);

   i = sscanf(mac_string,"%02X:%02X:%02X:%02X:%02X:%02X",
      (unsigned int *)&MAC_Add[0],(unsigned int *)&MAC_Add[1],(unsigned int *)&MAC_Add[2],
      (unsigned int *)&MAC_Add[3],(unsigned int *)&MAC_Add[4],(unsigned int *)&MAC_Add[5]);

   if (i != 6) // bad mac string
      return -1;

   for (i=0; i<6; i++)
      MAC[i]=(unsigned char)MAC_Add[i];

   return 0;
}



void Inet_PutMACinString(char *mac_string, unsigned char *MAC)
{
   unsigned int MAC_Add[6];
   int i;

   for (i=0; i<6; i++)
      MAC_Add[i]=(unsigned int)MAC[i];

   sprintf(mac_string, "%02X:%02X:%02X:%02X:%02X:%02X",
      (unsigned int)MAC_Add[0],(unsigned int)MAC_Add[1],(unsigned int)MAC_Add[2],
      (unsigned int)MAC_Add[3],(unsigned int)MAC_Add[4],(unsigned int)MAC_Add[5]);

}


socket_handle Inet_OpenSocket(char *host, short port)
{
   struct hostent *infh;
   struct sockaddr_in sa_in;
   socket_handle sh;
#ifdef CYGWIN
   WSADATA wsdata;
#endif

#ifdef DEBUG
   Debug_msg("Inet_OpenSocket -- host [%s] port [%d]", host, port);
#endif

#ifdef CYGWIN
   if ( WSAStartup(MAKEWORD(2, 2), &wsdata) != 0)
      ERROR_MSG("Cannot inizialize winsock WSAStartup()");
#endif

   bzero((char*)&sa_in, sizeof(sa_in));
   sa_in.sin_family = AF_INET;
   sa_in.sin_port = htons(port);

   if( (infh = gethostbyname(host)) )
      bcopy(infh->h_addr, (char*)&sa_in.sin_addr, infh->h_length);
   else
   {
      if ( (sa_in.sin_addr.s_addr = inet_addr(host)) == -1 )
         ERROR_MSG("Addresses doesn't mach");
   }

#ifdef CYGWIN
   if ( (sh.fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
#else
   if ( (sh = socket(AF_INET, SOCK_STREAM, 0)) < 0)
#endif
      ERROR_MSG("socket()");
   else
   {
#ifdef CYGWIN
      if ( connect(sh.fd, (struct sockaddr *)&sa_in, sizeof(sa_in)) < 0)
#else
      if ( connect(sh, (struct sockaddr *)&sa_in, sizeof(sa_in)) < 0)
#endif
         Error_msg("Can't connect to %s on port %d | %s\n\n", host, port, strerror(errno));
   }

#ifdef CYGWIN
   sh.sin = sa_in;
#endif

   return sh;
}


int Inet_CloseSocket(socket_handle sh)
{
#ifdef DEBUG
   Debug_msg("Inet_CloseSocket");
#endif

#ifdef CYGWIN
   WSACleanup();
   return closesocket(sh.fd);
#else
   return close(sh);
#endif

}


int Inet_Http_Send(socket_handle sh, char *payload)
{
#ifdef CYGWIN
   return sendto(sh.fd, (const char *)payload, strlen(payload), 0, (struct sockaddr *)&sh.sin, sizeof(sh.sin));
#else
   return write(sh, payload, strlen(payload));
#endif
}



int Inet_Http_Receive(socket_handle sh, char *payload, size_t size)
{
   int i = 0;
#ifdef CYGWIN
   int foo;
   while( i < size && recvfrom(sh.fd, payload + i++, 1, 0, (struct sockaddr *)&sh.sin, &foo) );
#else
   while( i < size && read(sh, payload + i++, 1) );
#endif
   return i;
}


int Inet_SendLargeTCPPacket(int sock, char *buffer, int len, int MTU)
{
   IP_header *ip;
   TCP_header *tcp;
   char *data;
   int datalen, totdatalen;

   if (len <= MTU+ETH_HEADER)
   {
      Inet_SendRawPacket(sock, buffer, len);
      return(0);
   }

   //Only for splitted TCP packets
   ip = (IP_header *) (buffer + ETH_HEADER);
   tcp = (TCP_header *) ((int)ip + ip->h_len * 4);
   data = (char *)((int)tcp + tcp->doff * 4);
   datalen = (int)ip + MTU - (int)data;
   totdatalen = (int)ip + ntohs(ip->t_len) - (int)data;
   ip->t_len = htons(MTU);
   ip->checksum = 0;
   ip->checksum = Inet_Forge_ChecksumIP( (unsigned short *) ip, sizeof(IP_header));
   tcp->checksum = 0;
   tcp->checksum = Inet_Forge_Checksum((unsigned short *)tcp, IPPROTO_TCP, ntohs(ip->t_len)-ip->h_len*4, ip->source_ip, ip->dest_ip);
   Inet_SendRawPacket(sock, buffer, MTU+ETH_HEADER);

   ip->t_len = htons(len - datalen - ETH_HEADER);

   ip->ident = htons ( ntohs(ip->ident) + 1 );
   ip->checksum = 0;
   ip->checksum = Inet_Forge_ChecksumIP( (unsigned short *) ip, sizeof(IP_header));
   memcpy(data , data+datalen, totdatalen-datalen);
   tcp->seq = htonl ( ntohl(tcp->seq) + datalen );
   tcp->checksum = 0;
   tcp->checksum = Inet_Forge_Checksum((unsigned short *)tcp, IPPROTO_TCP, ntohs(ip->t_len)-ip->h_len*4, ip->source_ip, ip->dest_ip);
   Inet_SendRawPacket(sock, buffer, ntohs(ip->t_len)+ETH_HEADER);

   return(1);
}

/* EOF */
