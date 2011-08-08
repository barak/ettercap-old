/*
    ettercap -- dryad -- passive info collector for the LAN

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

    $Id: ec_dryad.c,v 1.14 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#include <fcntl.h>
#include <math.h>
#include <ctype.h>

#include "include/ec_inet.h"
#include "include/ec_inet_forge.h"
#include "include/ec_inet_structures.h"
#include "include/ec_buffer.h"
#include "include/ec_error.h"
#include "include/ec_dissector.h"
#include "include/ec_thread.h"
#include "include/ec_decodedata.h"

// protos

pthread_t Dryad_Run(void);
void * Dryad_Main(void *);
void Dryad_Get_Banner(PASSIVE_DATA *, CONNECTION *, u_char, u_char *, int);

//----------------------------------------


pthread_t Dryad_Run(void)
{

#ifdef DEBUG
   Debug_msg("Dryad_Run");
#endif

   return ECThread_create("dryad", &Dryad_Main, NULL);

}



void * Dryad_Main(void *dummy)
{
   char *buf;
   int sock, MTU;
   u_long MyIP, NetMask;
   ETH_header  *eth;
   ARP_header *arp;
   IP_header *ip;
   ICMP_header *icmp;
   TCP_header *tcp;
   UDP_header *udp;
   u_char *tcp_opt, *tcp_data;
   int tcp_datalen, pck_len;
   PASSIVE_DATA data_to_ettercap;
   CONNECTION state_machine_data;

#ifdef DEBUG
   Debug_msg("Dryad_Main");
#endif

   sock = Inet_OpenRawSock(Options.netiface);
   Inet_GetIfaceInfo(Options.netiface, &MTU, NULL, &MyIP, &NetMask);

   MyIP = MyIP & NetMask;  // prepare it for later comparison...

   if (number_of_connections == -1) Inet_SetPromisc(Options.netiface);  // promisc mode only from interface 1

   buf = Inet_Forge_packet( MTU );

   fcntl(sock, F_SETFL, O_NONBLOCK);

   loop
   {
      short len=0;
      char goodpkt = 0;

      pthread_testcancel();

      memset(buf, 0, MTU);

      len = Inet_GetRawPacket(sock, buf, MTU, NULL);

      if (len > 0)
      {
         memset(&data_to_ettercap, 0, sizeof(PASSIVE_DATA));

// ==== ETHERNET LEVEL ====

         eth = (ETH_header *) buf;

         Inet_PutMACinString(data_to_ettercap.mac, eth->source_mac); // STORE THE MAC

// ==== ARP LEVEL ====

         if ( ntohs(eth->type) == ETH_P_ARP )
         {
            arp = (ARP_header *)(eth + 1);

            if (ntohs(arp->proto_type) != ETH_P_IP) continue;  // skip non ip arp packets

            if (ntohs(arp->opcode) == ARPOP_REQUEST)
            {
               Inet_PutMACinString(data_to_ettercap.mac, arp->source_add); // STORE THE MAC
                                                                           // overwrite the eth one because it is possible
                                                                           // that a proxy arp or a bridge is forwarding it
               strcpy(data_to_ettercap.ip, int_ntoa(arp->source_ip));      // STORE THE IP

               if ((*(u_long *)(arp->source_ip) & NetMask) != MyIP)    // Non Local IP
                  sprintf(data_to_ettercap.type, "NL");   // possible at this level ??? misconfigured switches ???

               goodpkt = 1;
            }
         }

// ==== IP LEVEL ====

         if ( ntohs(eth->type) == ETH_P_IP )
         {
            int TTL=0;  // fingerprint info...

            ip = (IP_header *)(eth + 1);

            strcpy(data_to_ettercap.ip, int_ntoa(ip->source_ip));    // STORE THE IP
            strcpy(state_machine_data.source_ip, int_ntoa(ip->source_ip));
            strcpy(state_machine_data.dest_ip, int_ntoa(ip->dest_ip));

            if ((ip->source_ip & NetMask) != MyIP)    // Non Local IP
               sprintf(data_to_ettercap.type, "NL");

            #define UPPER_LIMIT(x,y) ((x<y) ? x : y)
            TTL = UPPER_LIMIT(255, pow(2, ceil(log(ip->ttl)/log(2))));   // round the TTL to the nearest power of 2 (ceiling)
            data_to_ettercap.hop = TTL - ip->ttl + 1;
            if (ip->source_ip == inet_addr(Host_In_LAN[0].ip))    // Our IP is at distance ZERO !
               data_to_ettercap.hop = 0;
            #undef UPPER_LIMIT

            goodpkt = 1;

// ==== ICMP LEVEL ====

            if (ip->proto == IPPROTO_ICMP)
            {
               icmp = (ICMP_header *) ((int)ip + ip->h_len * 4);

               switch (icmp->type)
               {
                  case 11: // TTL-time-exceded
                  case 5:  // redirect
                  //case 3:   // Destination unreachable
                           sprintf(data_to_ettercap.type, "RT");      // this type is issued by a router
                           break;
               }

            }

// ==== UDP LEVEL ====

            if (ip->proto == IPPROTO_UDP)
            {
               udp = (UDP_header *) ((int)ip + ip->h_len * 4);

               if (ntohs(udp->source) >= 1024) continue;       // skip unusual port, because ports used
                                                               // from client side can be midetected as open

               data_to_ettercap.port = ntohs(udp->source);     // STORE THE UDP OPEN PORT
               data_to_ettercap.proto = 'U';
            }

// ==== TCP LEVEL ====

            if (ip->proto == IPPROTO_TCP)
            {
               int WIN=0, MSS=-1, WS=-1, S=0, N=0, D=0, T=0; //fingerprint infos...
               char WSS[3], _MSS[5];

               tcp = (TCP_header *) ((int)ip + ip->h_len * 4);
               tcp_opt = (u_char *)(tcp + 1);
               tcp_data = (u_char *)((int)tcp + tcp->doff * 4);
               tcp_datalen = (int)ip + ntohs(ip->t_len) - (int)tcp_data;

					pck_len = (int)tcp_data - (int)ip;

               state_machine_data.proto = 'T';
               state_machine_data.source_port = ntohs(tcp->source);
               state_machine_data.dest_port = ntohs(tcp->dest);

               data_to_ettercap.proto = 'T';

               if (tcp->flags & TH_SYN)   // only SYN or SYNACK packets
               {
                  if (tcp_datalen) continue;

                  if (ntohs(ip->frag_and_flags) & IP_DF) D = 1;   // don't fragment bit is set

                  WIN = ntohs(tcp->window);  // TCP window size

                  if (tcp_data != tcp_opt) // there are some tcp_option to be parsed
                  {
                     u_char *opt_ptr = tcp_opt;

                     while(opt_ptr < tcp_data)
                     {
                        switch(*opt_ptr)
                        {
                           case TCPOPT_EOL:        // end option
                              opt_ptr = tcp_data;  // exit
                              break;
                           case TCPOPT_NOP:
                              N = 1;
                              opt_ptr++;
                              break;
                           case TCPOPT_SACKOK:
                              S = 1;
                              opt_ptr += 2;
                              break;
                           case TCPOPT_MAXSEG:
                              opt_ptr += 2;
                              MSS = ntohs(ptohs(opt_ptr));
                              opt_ptr += 2;
                              break;
                           case TCPOPT_WSCALE:
                              opt_ptr += 2;
                              WS = *opt_ptr;
                              opt_ptr++;
                              break;
                           case TCPOPT_TIMESTAMP:
                              T = 1;
                              opt_ptr++;
                              opt_ptr += (*opt_ptr - 1);
                              break;
                           default:
                              opt_ptr++;
                              opt_ptr += (*opt_ptr - 1);
                              break;
                        }
                     }
                  }

                  if (WS == -1) sprintf(WSS, "WS");
                  else snprintf(WSS, sizeof(WSS), "%02d", WS);

                  if (MSS == -1) sprintf(_MSS, "_MSS");
                  else snprintf(_MSS, sizeof(_MSS), "%04X", MSS);

                  if (tcp->flags & TH_ACK)
                  {

// TODO: dont show FPT passive port as opened

                     if (ntohs(tcp->dest) != 20)   // skip ports opened by ftp channel
                        data_to_ettercap.port = ntohs(tcp->source);     // STORE THE TCP OPEN PORT
                  }

                  snprintf(data_to_ettercap.fingerprint, sizeof(data_to_ettercap.fingerprint),
                           "%04X:%s:%02X:%s:%d:%d:%d:%d:%c:%02X",
                           WIN, _MSS, TTL, WSS , S, N, D, T, (tcp->flags & TH_ACK) ? 'A' : 'S', pck_len);

               } // if SYN

               Dryad_Get_Banner(&data_to_ettercap, &state_machine_data, tcp->flags, tcp_data, tcp_datalen);

            } // if TCP
         }
      } // datalen > 0
      else
         usleep(1);

      if (goodpkt) Decodedata_MakePassiveList(&data_to_ettercap);
   }

}



void Dryad_Get_Banner(PASSIVE_DATA *data_to_ettercap, CONNECTION *state_machine_data, u_char flags, u_char *data, int datalen)
{
   char info[20];
   int i;

   if ( (flags & TH_SYN) && (flags & TH_ACK) )  // SYN + ACK
   {
      sprintf(info, "%d", state_machine_data->source_port);
      Dissector_StateMachine_SetStatus(state_machine_data, 2, info);
   }
   else if ( (flags & TH_ACK) && (Dissector_StateMachine_GetStatus(state_machine_data, NULL) == 2) )
   {
      Dissector_StateMachine_SetStatus(state_machine_data, 3, NULL);
   }
   else     // probably PSH
   {
      if ( Dissector_StateMachine_GetStatus(state_machine_data, info) == 3 )  // the connection is right after the 3 way handshaking
      {

         if (state_machine_data->source_port != atoi(info))                   // and it is sending from server to client
            return;                                                           // info was stored at the SYN+ACK

         data[datalen] = 0;

         if (state_machine_data->source_port == 80)   // http banner are different...
         {                                            // we have to find them in the http header
            char *ptr;

            if ( (ptr = strstr(data, "Server:")) )
            {
               for (i=0; i<datalen; i++)
                     if ( data[i] == '\r' ) data[i] = 0;

               strlcpy(data_to_ettercap->banner, ptr+8, sizeof(data_to_ettercap->banner));

               data_to_ettercap->port = state_machine_data->source_port;

               Dissector_StateMachine_SetStatus(state_machine_data, 0, NULL);
            }
         }
         else
         {
            u_char *ptr = data;
            for ( ; ptr < data + datalen ; )
            {
               if ( *ptr == 0xff )     // skip telnet options (if it is telnet obviously)
               {
                  if (*(ptr+1) == 0xf0 ) ptr += 2;
                  else if (*(ptr+1) != 0xfa ) ptr += 3;
                  else if (*(ptr+1) == 0xfa )
                  {
                     ptr++;
                     while(*++ptr != 0xff)
                        ;
                  }
               }
               else if ( *ptr == '\r' || *ptr == '\n' || *ptr == 0) ptr++;
               else break;
            }

            if (strlen(ptr))
            {
               for (i=0 ; i < strlen(ptr); i++ )
               {
                  if (!isprint(ptr[i]))
                  {
                     ptr[i]=0;
                     break;
                  }
                  if (ptr[i] == '\n' || ptr[i] == '\r') ptr[i] = ' ';
               }

               strlcpy(data_to_ettercap->banner, ptr, sizeof(data_to_ettercap->banner));

               data_to_ettercap->port = state_machine_data->source_port;
               Dissector_StateMachine_SetStatus(state_machine_data, 0, NULL);
            }
         }
      }
   }
}

/* EOF */
