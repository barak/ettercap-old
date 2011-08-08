/*
    ettercap -- module for logging into different files

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

    $Id: ec_logtofile.c,v 1.7 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#include <time.h>

#include "include/ec_inet.h"
#include "include/ec_error.h"
#include "include/ec_fingerprint.h"
#include "include/ec_inet_structures.h"
#include "include/ec_decodedata.h"

// protos

void LogToFile(SNIFFED_DATA *data);
void LogToFile_Collect(CONNECTION *data);

void LogToFile_FilteredData(u_char * buf_ip);
char *LogToFile_DumpPass(void);
char *LogToFile_MakePassiveReport(char mode);

// -------------------------------

void LogToFile_Collect(CONNECTION *data)
{
   FILE *fto;
   static char filename[50] = "";
   time_t tt = time(NULL);
   struct tm *dd = localtime(&tt);

#ifdef DEBUG
   Debug_msg("LogToFile_Collect");
#endif

   if (!strcmp(filename, ""))
      snprintf(filename, sizeof(filename), "%04d%02d%02d-Collected-Passwords.log", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday);

   fto = fopen(filename, "a");
   if (fto == NULL)
      ERROR_MSG("fopen()");

   fprintf(fto, "\n\n%02d:%02d:%02d  %s:%d <--> %s:%d%15s\n\n", dd->tm_hour, dd->tm_min, dd->tm_sec,
                        data->source_ip,
                        data->source_port,
                        data->dest_ip,
                        data->dest_port,
                        data->type
                        );

   fprintf(fto, "%s\n", data->user);
   fprintf(fto, "%s\n", data->pass);
   if (strlen(data->info))
      fprintf(fto, "\n%s\n", data->info);
   fflush(fto);
   fclose(fto);

}


void LogToFile(SNIFFED_DATA *data)
{
   FILE *fto;
   char filename[50];
   time_t tt = time(NULL);
   struct tm *dd = localtime(&tt);


   snprintf(filename, sizeof(filename), "%04d%02d%02d-%c-%s:%d-%s:%d.log", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday,
                        data->proto, data->source_ip, data->source_port, data->dest_ip, data->dest_port );

   fto = fopen(filename, "a");
   if (fto == NULL)
      ERROR_MSG("fopen()");


   write(fileno(fto), data->data, data->datasize);

   if ( (data->flags & TH_RST) || (data->flags & TH_FIN) )
      fprintf(fto, "\n\n| CONNECTION CLOSED ON %02d:%02d:%02d |\n\n",  dd->tm_hour, dd->tm_min, dd->tm_sec);

   fflush(fto);
   fclose(fto);
}



void LogToFile_FilteredData(u_char * buf_ip)
{
   IP_header *ip;
   UDP_header *udp;
   TCP_header *tcp;
   u_char *data = NULL;
   short datalen = 0;
   FILE *fto;
   char logname[100];
   time_t tt = time(NULL);
   struct tm *dd = localtime(&tt);


   ip = (IP_header *) buf_ip;

   if (ip->proto == IPPROTO_UDP)
   {
      udp = (UDP_header *) ((int)ip + ip->h_len * 4);
      data = (char *)((int)udp + UDP_HEADER);
      datalen = ntohs(udp->len) - UDP_HEADER;
      snprintf(logname, sizeof(logname), "%04d%02d%02d-Filtered-U-%s:%d-", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday,
                        int_ntoa(ip->source_ip),
                        ntohs(udp->source));
      snprintf(logname, sizeof(logname), "%s%s:%d.log", logname, int_ntoa(ip->dest_ip), ntohs(udp->dest) ); // damned static in inet_ntoa...
   }
   else if (ip->proto == IPPROTO_TCP)
   {
      tcp = (TCP_header *) ((int)ip + ip->h_len * 4);
      data = (char *)((int)tcp + tcp->doff * 4);
      datalen = (int)ip + ntohs(ip->t_len) - (int)data;
      snprintf(logname, sizeof(logname), "%04d%02d%02d-Filtered-T-%s:%d-", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday,
                        int_ntoa(ip->source_ip),
                        ntohs(tcp->source));
      snprintf(logname, sizeof(logname), "%s%s:%d.log", logname, int_ntoa(ip->dest_ip), ntohs(tcp->dest) ); // damned static in inet_ntoa...
   }

   if (data && datalen)
   {
      fto = fopen(logname, "a");
      if (fto == NULL)
         ERROR_MSG("fopen()");
      write(fileno(fto), data, datalen);
      fflush(fto);
      fclose(fto);
   }

}


char *LogToFile_DumpPass(void)
{
   static char logname[100];
   FILE *fto;
   int i;
   time_t tt = time(NULL);
   struct tm *dd = localtime(&tt);

#ifdef DEBUG
   Debug_msg("LogToFile_DumpPass");
#endif

   snprintf(logname, sizeof(logname), "%04d%02d%02d-%02d:%02d:-Dumped_Password.log", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday, dd->tm_hour, dd->tm_min);

   fto = fopen(logname, "a");
   if (fto == NULL)
      ERROR_MSG("fopen()");

   for (i=0; i < number_of_connections; i++)
   {
      if (Conn_Between_Hosts[i].user[0] != 0 &&  Conn_Between_Hosts[i].pass[0] != 0)
      {
         fprintf(fto, "\n\n%s:%d -> %s:%d\t\t%s\n\n", Conn_Between_Hosts[i].source_ip,
                                                      Conn_Between_Hosts[i].source_port,
                                                      Conn_Between_Hosts[i].dest_ip,
                                                      Conn_Between_Hosts[i].dest_port,
                                                      Conn_Between_Hosts[i].type
                                                      );
         fprintf(fto, "%s\n", Conn_Between_Hosts[i].user);
         fprintf(fto, "%s\n", Conn_Between_Hosts[i].pass);
         if (strlen(Conn_Between_Hosts[i].info))
            fprintf(fto, "\n%s\n", Conn_Between_Hosts[i].info);
         fflush(fto);
      }
      else if (strlen(Conn_Between_Hosts[i].info))
      {
         fprintf(fto, "\n\n%s:%d -> %s:%d\t\t%s\n\n", Conn_Between_Hosts[i].source_ip,
                                                      Conn_Between_Hosts[i].source_port,
                                                      Conn_Between_Hosts[i].dest_ip,
                                                      Conn_Between_Hosts[i].dest_port,
                                                      Conn_Between_Hosts[i].type
                                                      );
         fprintf(fto, "USER : \n");
         fprintf(fto, "PASS : \n");
         if (strlen(Conn_Between_Hosts[i].info))
            fprintf(fto, "\n%s\n", Conn_Between_Hosts[i].info);
         fflush(fto);
      }
   }

   fclose(fto);
   return logname;
}




char *LogToFile_MakePassiveReport(char mode)
{
   static char logname[100];
   FILE *fto;
   int i;
   time_t tt = time(NULL);
   struct tm *dd = localtime(&tt);
   u_long MyIP, NetMask;
   struct open_ports *current;

#ifdef DEBUG
   Debug_msg("LogToFile_MakePassiveReport");
#endif

   if (mode == 'l')
      snprintf(logname, sizeof(logname), "%04d%02d%02d-%02d:%02d-Passive_Local_Report.log", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday, dd->tm_hour, dd->tm_min);
   else if (mode == 'L')
      snprintf(logname, sizeof(logname), "%04d%02d%02d-%02d:%02d-Passive_Full_Report.log", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday, dd->tm_hour, dd->tm_min);

   fto = fopen(logname, "a");
   if (fto == NULL)
      ERROR_MSG("fopen()");


   Inet_GetIfaceInfo(Options.netiface, NULL, NULL, &MyIP, &NetMask);

   fprintf(fto, "=================================================================\n");
   fprintf(fto, " ETTERCAP REPORT for  %s", int_ntoa(MyIP));
   fprintf(fto, "       netmask: %s\n", int_ntoa(NetMask));
   fprintf(fto, "=================================================================\n");

   for (i=0; i < number_of_passive_hosts; i++)
   {
      if (mode == 'l' && !strcmp(Passive_Host[i].type, "NL")) continue; // skip non local ip

      fprintf(fto, "\n=================================================================\n");
      fprintf(fto, "\nIP & MAC address    : %-15s%28s\n\n", Passive_Host[i].ip, Passive_Host[i].mac );

      fprintf(fto, "HOSTNAME            : %s\n\n", Inet_HostName(Passive_Host[i].ip));

      if (!strcmp(Passive_Host[i].type, "GW"))
         fprintf(fto, "**** THIS HOST IS A GATEWAY FOR IPs LIKE %s ****\n\n", Passive_Host[i].gwforthis);

      if (!strcmp(Passive_Host[i].type, "RT"))
         fprintf(fto, "**** THIS HOST ATCS AS A ROUTER FOR THE LAN ****\n\n");

      if (!strcmp(Passive_Host[i].type, "NL"))
         fprintf(fto, "**** THIS HOST DOESN'T BELONG TO THE NETMASK ****\n\n");

      if (Passive_Host[i].os[0] == 0 && Passive_Host[i].os[1] != 0)
      {
         fprintf(fto, "UNKNOWN FINGERPRINT : %s\n",  Passive_Host[i].fingerprint);
         fprintf(fto, "THE NEAREST IS      : %s\n\n", Passive_Host[i].os + 1);
      }
      else
         fprintf(fto, "OPERATING SYSTEM    : %s\n\n",  Passive_Host[i].os);

      fprintf(fto, "NETWORK ADAPTER     : %s\n\n",  Fingerprint_MAC(Passive_Host[i].mac));

      fprintf(fto, "DISTANCE IN HOP     : %d\n\n", Passive_Host[i].hop);

      if (!LIST_EMPTY(&Passive_Host[i].tcp_ports))
      {
         LIST_FOREACH(current, &Passive_Host[i].tcp_ports, next)
         {
            if (current == LIST_FIRST(&Passive_Host[i].tcp_ports))
               fprintf(fto, "OPEN PORTS  (tcp)   : %-5d  %s\n", current->port, Decodedata_GetType('T', current->port, current->port) );
            else
               fprintf(fto, "                    : %-5d  %s\n", current->port, Decodedata_GetType('T', current->port, current->port) );
         }
      }
      else
         fprintf(fto, "OPEN PORTS  (tcp)   : NONE\n");

      fprintf(fto, "\n");

      if (!LIST_EMPTY(&Passive_Host[i].udp_ports))
      {
         LIST_FOREACH(current, &Passive_Host[i].udp_ports, next)
         {
            if (current == LIST_FIRST(&Passive_Host[i].udp_ports))
               fprintf(fto, "OPEN PORTS  (udp)   : %-5d  %s\n", current->port, Decodedata_GetType('U', current->port, current->port) );
            else
               fprintf(fto, "                    : %-5d  %s\n", current->port, Decodedata_GetType('U', current->port, current->port) );
         }
      }
      else
         fprintf(fto, "OPEN PORTS  (udp)   : NONE\n");

      fprintf(fto, "\n");

      if (!LIST_EMPTY(&Passive_Host[i].tcp_ports))
      {
         LIST_FOREACH(current, &Passive_Host[i].tcp_ports, next)
         {
            if (!strlen(current->banner)) continue;
            if (current == LIST_FIRST(&Passive_Host[i].tcp_ports))
               fprintf(fto, "TCP SERVICES BANNER : %-5d  %s\n", current->port, current->banner );
            else
               fprintf(fto, "                    : %-5d  %s\n", current->port, current->banner );
         }
      }

      fprintf(fto, "\n=================================================================\n");
   }

   fclose(fto);
   return logname;
}


/* EOF */
