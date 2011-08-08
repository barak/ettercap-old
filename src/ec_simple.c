/*
    ettercap -- module for NON ncurses interface

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

    $Id: ec_simple.c,v 1.15 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#include <fcntl.h>
#ifndef CYGWIN
	#include <sys/wait.h>
#endif
#include <signal.h>

#include "include/ec_error.h"
#include "include/ec_inet.h"
#include "include/ec_inet_structures.h"
#include "include/ec_inet_forge.h"
#include "include/ec_decodedata.h"
#include "include/ec_dissector.h"
#include "include/ec_illithid.h"
#include "include/ec_doppleganger.h"
#include "include/ec_grell.h"
#include "include/ec_buffer.h"
#include "include/ec_plugins.h"
#include "include/ec_fingerprint.h"
#include "include/ec_logtofile.h"
#include "include/ec_filterdrop.h"
#include "include/ec_dryad.h"
#include "include/ec_thread.h"

#if defined (HAVE_TERMIOS_H) && !defined (CYGWIN)
   #include <termios.h>

   struct termios old_tc;
   struct termios new_tc;

   void set_raw_term(void);
   void reset_term(void);

#endif

#define ASCII_VIEW      0
#define HEX_VIEW        1
#define TEXT_VIEW       2

extern char *Execute_Plugin;

// protos...
#ifdef PERMIT_PLUGINS
   void Simple_Plugin(void);
#endif
void Simple_HostList(void);
void Simple_Run(void);
void Simple_CheckForPoisoner(void);
void Simple_FingerPrint(void);
void Simple_CheckForSwitch(void);
void Simple_Demonize(void);
void Simple_CreateCertFile(void);
void Simple_PassiveScan(void);

//---------------------------------

void Simple_HostList(void)
{
   int j;

#ifdef DEBUG
   Debug_msg("Simple_HostList");
#endif

   printf("\nHost in this LAN:\n\n");

   for(j=0; j<number_of_hosts_in_lan; j++)
   {
      printf("%3d) %-20s %s\t%s\n", j+1, Host_In_LAN[j].ip, Host_In_LAN[j].mac, Host_In_LAN[j].name);
   }

   printf("\n");
}


void Simple_FingerPrint(void)
{
   int IP;
   char MAC[6];
   char MACs[17];

#ifdef DEBUG
   Debug_msg("Simple_FingerPrint -- [%s]", Host_Dest.ip);
#endif

   IP = inet_addr(Host_Dest.ip);
   memcpy(MAC, Inet_MacFromIP(IP), 6);
   Inet_PutMACinString(MACs, MAC);

   printf("\n\nFingerprinting %s...\n\n", Host_Dest.ip);

   printf("\n\033[36mOperating System:\033[0m\n\n%s\n", Fingerprint_OS(Host_Dest.ip) );
   printf("\n\033[36mNetwork Adapter :\033[0m\n\n%s\n", Fingerprint_MAC(MACs) );

   printf("\n");
}



void Simple_CreateCertFile(void)
{

#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)

   FILE *fta, *ftr;
   char line[512];

#ifdef DEBUG
   Debug_msg("Simple_CreateCertFile");
#endif

   fprintf(stdout, "\nGenerating Openssl [%s] certificate...\n\n", CERT_FILE);

   if ( !fork() )
   {
      if ( execl( OPENSSL_PATH, "openssl", "genrsa", "-out", CERT_FILE, "1024", NULL) == -1)
         Error_msg("Could not launch openssl --> " OPENSSL_PATH);
   }
   else
      wait(NULL);

   if ( !fork() )
   {
      if ( execl( OPENSSL_PATH, "openssl", "req", "-new", "-key", CERT_FILE, "-out", CERT_FILE ".csr", NULL) == -1)
         Error_msg("Could not launch openssl --> " OPENSSL_PATH);
   }
   else
      wait(NULL);

   if ( !fork() )
   {
      if ( execl( OPENSSL_PATH, "openssl", "x509", "-req", "-days", "365", "-in", CERT_FILE ".csr", "-signkey", CERT_FILE, "-out", CERT_FILE ".new", NULL) == -1)
         Error_msg("Could not launch openssl --> " OPENSSL_PATH);
   }
   else
      wait(NULL);

   fta = fopen(CERT_FILE, "a");
   ftr = fopen(CERT_FILE ".new", "r");

   while (fgets(line, sizeof(line), ftr))
      fprintf(fta, "%s", line);

   fclose(fta);
   fclose(ftr);

   unlink(CERT_FILE ".new");
   unlink(CERT_FILE ".csr");

   fprintf(stdout, "\nOpenssl certificate generated in ./%s\n\n", CERT_FILE);
#else
   Error_msg("ettercap was compiled without HTTPS support...");
#endif
   exit(0);
}



void Simple_CheckForSwitch(void)
{
   short type;

   switch(type = Inet_CheckSwitch())
   {
      case 0: printf("\n Link Type: unknown\n");
              break;
      case 1: printf("\n Link Type: HUB\n");
              break;
      case 2: printf("\n Link Type: SWITCH\n");
              break;
   }

}



void Simple_CheckForPoisoner(void)
{
   SniffingHost *SniffList;
   int i;
   short found = 0;


#ifdef DEBUG
   Debug_msg("Simple_CheckForPoisoner");
#endif


   printf("\nChecking for poisoners...\n\n");

   SniffList = Inet_NoSniff();

   for (i=0; i<number_of_hosts_in_lan; i++)
   {
      if (SniffList[i].mode == 0) break;
      if (SniffList[i].mode == 1)
      {
         found = 1;
         printf(" %s is replying for %s\n", Host_In_LAN[SniffList[i].Host_Index1].ip, Host_In_LAN[SniffList[i].Host_Index2].ip);
      }

      if (SniffList[i].mode == 2)
      {
         found = 1;
         printf(" MAC of %s and %s are identical !\n",Host_In_LAN[SniffList[i].Host_Index1].ip,Host_In_LAN[SniffList[i].Host_Index2].ip);
      }

   }

   if (!found)
      printf(" No poisoners found in this lan (seems to be safe)\n\n");

   free(SniffList);
}

#ifdef PERMIT_PLUGINS

void Simple_Plugin(void)
{
#ifdef DEBUG
   Debug_msg("Simple_Plugin -- %s", Execute_Plugin);
#endif

   if (strcmp(Host_Source.name, ""))
      strcpy(Host_Source.ip, Inet_NameToIp(Host_Source.name));

   if (strcmp(Host_Dest.name, ""))
      strcpy(Host_Dest.ip, Inet_NameToIp(Host_Dest.name));

#ifdef DEBUG
   Debug_msg("Simple_Plugin -- [%s] [%s] [%s] [%s]", Host_Source.name, Host_Source.ip, Host_Dest.name, Host_Dest.ip );
#endif

   if (!strcmp(Execute_Plugin, "list"))
   {
      char ** plug_list, ** current;

      plug_list = Plugin_ExtList();

      if (!*plug_list)
         Error_msg("\n NO available plugins found in %s or ./ !!\n", PLUGIN_PATH);

      fprintf(stdout, "\n Available Plugins :\n\n");

      for (current = plug_list; *current; current++)
      {
        fprintf(stdout, "%s", *current);
        free(*current);
      }
      free(plug_list);
   }
   else
   {
      if (!Plugin_RunExt(Execute_Plugin))
      {
         fprintf(stderr, "\nPlugin \"%s\" NOT found in %s or in ./ !\n", Execute_Plugin, PLUGIN_PATH);
         fprintf(stderr, "\n'ettercap -Np list' to view the available ones.\n\n");
      }
   }

}

#endif


void Simple_Demonize(void)
{
 pid_t pid;

#ifdef DEBUG
   Debug_msg("Simple_Demonize");
#endif

   if((signal(SIGTTOU, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal()");

   if((signal(SIGTTIN, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal()");

   if((signal(SIGTSTP, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal()");

   if((signal(SIGHUP, SIG_IGN)) == SIG_ERR)
      ERROR_MSG("signal()");

   if((pid = fork()) < 0)
      ERROR_MSG("fork()");
   else if(pid != 0)
      Error_msg("ettercap demonized with PID: %d", pid);

   if(setsid() == -1)
      ERROR_MSG("setsid()");


}


#if defined (HAVE_TERMIOS_H) && !defined (CYGWIN)

void set_raw_term()        // taken from readchar.c, by M. Andreoli (2000)
{
    tcgetattr(0, &old_tc);
    new_tc = old_tc;
    new_tc.c_lflag &= ~(ECHO | ICANON);   /* raw output */
    new_tc.c_cc[VTIME] = 1;

    tcsetattr(0, TCSANOW, &new_tc);
}

void reset_term()          // taken from readchar.c, by M. Andreoli (2000)
{
    tcsetattr(0, TCSANOW, &old_tc);
}

#endif


void Simple_Run(void)
{
   pthread_t Illithid_pid = 0, Dopple_pid = 0;
   #if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
      pthread_t Grell_pid = 0;
   #endif
   int i, index_source=-1, index_dest=-1;
   char view = ASCII_VIEW;
   char stop = 0;
   fd_set msk_fd;
   struct timeval TimeOut;
   SNIFFED_DATA data_from_illithid;
   int datalen = 0;
   char source[20], dest[20];
   char proto = 'T', mode = IPBASED;
   struct in_addr addr;
   TIME_DECLARE;

   if (Options.udp) proto = 'U';

   number_of_connections = 0;

#ifdef DEBUG
   Debug_msg("Simple_Run - name - [%s][%s]", Host_Dest.name, Host_Source.name);
   Debug_msg("Simple_Run -  IP  - [%s][%s]", Host_Dest.ip, Host_Source.ip);
   Debug_msg("Simple_Run - port - [%d][%d]", Host_Dest.port, Host_Source.port);
   Debug_msg("Simple_Run -  MAC - [%s][%s]", Host_Dest.mac, Host_Source.mac);
   if (Options.sniff)      Debug_msg("Simple_Run - %c - sniff", proto);
   if (Options.arpsniff)   Debug_msg("Simple_Run - %c - arpsniff", proto);
   if (Options.macsniff)   Debug_msg("Simple_Run - %c - macsniff", proto);
#endif

   if (Options.hexview)
      view = HEX_VIEW;

   if (Options.quiet)
      Simple_Demonize();

   if (strcmp(Host_Source.name, ""))
   {
      strcpy(Host_Source.ip, Inet_NameToIp(Host_Source.name));
      strcpy(source, Host_Source.ip);
   }
   else
      strcpy(source, "ANY");

   if (strcmp(Host_Dest.name, ""))
   {
      strcpy(Host_Dest.ip, Inet_NameToIp(Host_Dest.name));
      strcpy(dest, Host_Dest.ip);
   }
   else
      strcpy(dest, "ANY");


   if (!Options.silent)
   {
      for(i=0; i<number_of_hosts_in_lan; i++)
      {
         if ( !strcmp(Host_Source.ip, Host_In_LAN[i].ip) )
         {
            index_source = i;
            strcpy(Host_Source.mac, Host_In_LAN[i].mac);
         }
         if ( !strcmp(Host_Dest.ip, Host_In_LAN[i].ip) )
         {
            index_dest = i;
            strcpy(Host_Dest.mac, Host_In_LAN[i].mac);
         }
      }

      if ( index_source < 0 && strcmp(Host_Source.name, ""))
      {
         if (!strcmp(Inet_MacFromIP(inet_addr(Host_Source.ip)), "\xff\xff\xff\xff\xff\xff"))
            Error_msg("Source host %s (%s) not found !!", Host_Source.name, Host_Source.ip);
         else
            Inet_PutMACinString(Host_Source.mac, Inet_MacFromIP(inet_addr(Host_Source.ip)));
      }

      if ( index_dest < 0 && strcmp(Host_Dest.name, ""))
      {
         if (!strcmp(Inet_MacFromIP(inet_addr(Host_Dest.ip)), "\xff\xff\xff\xff\xff\xff"))
            Error_msg("Dest host %s (%s) not found !!", Host_Dest.name, Host_Dest.ip);
         else
            Inet_PutMACinString(Host_Dest.mac, Inet_MacFromIP(inet_addr(Host_Dest.ip)));
      }
   }

   if ( !strcmp(Host_Source.ip, Host_Dest.ip) && strcmp(Host_Source.ip, "") )
      Error_msg("SOURCE and DEST IP address must be different !!");

   if (Options.arpsniff)
      if ( (!strcmp(Host_Source.ip, Inet_MyIPAddress())) || (!strcmp(Host_Dest.ip, Inet_MyIPAddress())) )
         Error_msg("CAN'T arpsniff yourself !!");

   if (Options.arpsniff)
   {
      if (strcmp(Host_Source.ip, "") || (number_of_hosts_in_lan > 1)) // arp based
         mode = ARPBASED;
      else
         mode = PUBLICARP;
   }
   else if (Options.sniff)
      mode = IPBASED;
   else if (Options.macsniff)
      mode = MACBASED;

   if (Options.filter)
   {
      if (FilterDrop_CheckMode(Filter_Array_Source, mode))
         Error_msg("Source filter chains incompatible with current sniff mode... re-Edit it !");

      if (FilterDrop_CheckMode(Filter_Array_Dest, mode))
         Error_msg("Dest filter chains incompatible with current sniff mode... re-Edit it !");
   }


   // it is ok...

   if (Options.arpsniff)      // Doppleganger born...
   {
      Inet_DisableForwarding();
      Dopple_pid = Doppleganger_Run(Options.netiface, Host_Source.ip, Host_Dest.ip, Host_Source.mac, Host_Dest.mac);
   }

   if (!Options.quiet) printf("\nPress 'h' for help...\n\n");

   pipe_with_illithid_data = Buffer_Create(5.0e5); // 500 Kb

   if (!Options.quiet && Options.reverse) printf(" Reverse");

   switch(mode)
   {
      case ARPBASED:
         if (!Options.quiet) printf(" Sniffing (ARP based) : %s:%d <--> %s <--> %s:%d\n\n", source, Host_Source.port, Inet_MyIPAddress(), dest, Host_Dest.port);
         if (!Options.collect) Connection_Mode=0;
         Illithid_pid = Illithid_ARPBased_GetConnections(Options.netiface, Host_Source.ip,  Host_Dest.ip, Host_Source.mac, Host_Dest.mac);
         #if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
            Grell_pid = Grell_Run();
         #endif
         break;

      case PUBLICARP:
         if (!Options.quiet) printf(" Sniffing (PUBLIC ARP) : %s:%d --> %s --> %s:%d  (half-duplex)\n\n", source, Host_Source.port, Inet_MyIPAddress(), dest, Host_Dest.port);
         if (!Options.collect) Connection_Mode=0;
         Illithid_pid = Illithid_PublicARP_GetConnections(Options.netiface, Host_Source.ip,  Host_Dest.ip, Host_Source.mac, Host_Dest.mac);
         #if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
            Grell_pid = Grell_Run();
         #endif
         break;

      case IPBASED:
         if (!Options.quiet) printf(" Sniffing (IP based): %s:%d <--> %s:%d\n\n", dest, Host_Dest.port, source, Host_Source.port );
         if (!Options.collect) Connection_Mode=0;
         Illithid_pid = Illithid_IPBased_GetConnections(Options.netiface, Host_Source.ip, Host_Dest.ip);
         break;

      case MACBASED:
         if (!strcmp(Host_Dest.mac, "")) strcpy(dest, "ANY");
         else strcpy(dest, Host_Dest.mac);
         if (!strcmp(Host_Source.mac, "")) strcpy(source, "ANY");
         else strcpy(source, Host_Source.mac);
         if (!Options.quiet) printf(" Sniffing (MAC based): %s <--> %s\n\n", dest, source);
         if (!Options.collect) Connection_Mode=0;
         Illithid_pid = Illithid_MACBased_GetConnections(Options.netiface, Host_Dest.mac, Host_Source.mac);
         break;
   }

   switch (proto)
   {
      case 'T': printf(" TCP packets only... (default)\n\n"); break;
      case 'U': printf(" UDP packets only...\n\n"); break;
   }


   if (!Options.quiet && Options.collect) printf("Collecting passwords... \n\n");

   memset(&TimeOut, 0, sizeof(TimeOut));  //  timeout = 0
   FD_ZERO(&msk_fd);

   if(!Options.quiet)
   {
      #if defined (HAVE_TERMIOS_H) && !defined (CYGWIN)
         set_raw_term();   // non blocking stdin... yes this work !!
      #else
         #ifdef DEBUG
            Debug_msg("Simple_Run -- NO TERMIOS_H");
         #endif
         fcntl(0, F_SETFL, O_NONBLOCK);   // stdin non blocking... seems to be a non working method for me...
      #endif
   }

   current_illithid_data.proto = proto;
   current_illithid_data.source_port = Host_Source.port;
   current_illithid_data.dest_port = Host_Dest.port;

   if (inet_aton(Host_Source.ip, &addr))
      current_illithid_data.source_ip = ntohl(addr.s_addr);
   if (inet_aton(Host_Dest.ip, &addr))
      current_illithid_data.dest_ip =  ntohl(addr.s_addr);

   TIME_START;

   loop
   {

      FD_SET(0, &msk_fd);

      select(FOPEN_MAX, &msk_fd, (fd_set *) 0, (fd_set *) 0, &TimeOut);

      if (FD_ISSET(0, &msk_fd))
      {
         char ch = 0;
         ch = getchar();
         switch(ch)
         {
            case 'A':
            case 'a':
                  if (!Options.collect)
                  {
                     printf("\n\nAscii mode...\n\n");
                     view = ASCII_VIEW;
                  }
                  break;

            case 'X':
            case 'x':
                  if (!Options.collect)
                  {
                     printf("\n\nHex mode...\n\n");
                     view = HEX_VIEW;
                  }
                  break;

            case 'T':
            case 't':
                  if (!Options.collect)
                  {
                     printf("\n\nTEXT only mode...\n\n");
                     view = TEXT_VIEW;
                  }
                  break;

            case 'L':
            case 'l':
                  if (Options.logtofile)
                  {
                     printf("\n\nStop logging to file(s)...\n\n");
                     Options.logtofile = 0;
                  }
                  else
                  {
                     printf("\n\nLogging to file(s)...\n\n");
                     Options.logtofile = 1;
                  }
                  break;

            case ' ':
                  if (stop == 1)
                  {
                     printf("\n\nLet's go...\n\n");
                     stop = 0;
                  }
                  else
                  {
                     printf("\n\nStopped...\n\n");
                     stop = 1;
                  }
                  break;

            case 'S':
            case 's':
                  if (Options.filter)
                  {
                     filter_on_source = (filter_on_source) ? 0 : 1;
                     printf("\n\nFILTERS: on source %d | on dest %d\n\n", filter_on_source, filter_on_dest);
                  }
                  break;

            case 'D':
            case 'd':
                  if (Options.filter)
                  {
                     filter_on_dest = (filter_on_dest) ? 0 : 1;
                     printf("\n\nFILTERS: on source %d | on dest %d\n\n", filter_on_source, filter_on_dest);
                  }
                  break;

            case 'H':
            case 'h':
                  printf("\n\n[qQ]  - quit\n");
                  if (!Options.collect)
                  {
                     printf(    "[aA]  - dump data in ascii mode\n");
                     printf(    "[xX]  - dump data in hex mode\n");
                     printf(    "[tT]  - dump data in text only mode\n");
                  }
                  if (Options.filter)
                  {
                     printf(    "[sS]  - set/unset filter on source\n");
                     printf(    "[dD]  - set/unset filter on dest\n");
                  }
                  printf(    "[lL]  - log all trafic to file(s)\n");
                  printf(    "space - stop/cont sniffing\n\n");
                  break;

            case 'Q':
            case 'q':
#if defined (HAVE_TERMIOS_H) && !defined (CYGWIN)
                  if(!Options.quiet) reset_term();
#endif
                  printf("\n\n\nShutting down all threads... ");
                  fflush(stdout);
                  ECThread_destroy(Illithid_pid);
                  if (Dopple_pid) ECThread_destroy(Dopple_pid);
                  #if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
                     if (Grell_pid) ECThread_destroy(Grell_pid);
                  #endif
                  printf("Done.\n\n");
                  exit(0);
                  break;
         }
      }

      if (!Options.collect)
         datalen = Buffer_Get(pipe_with_illithid_data, &data_from_illithid, sizeof(SNIFFED_DATA));

      if (datalen > 0 || Connection_Mode)
      {
         time_t tt = time(NULL);
         struct tm *dd = localtime(&tt);

         if (Options.collect)
         {
            int j;

            for (j=0; j < number_of_connections; j++)
            {
               if (Conn_Between_Hosts[j].user[0] != 0 &&  Conn_Between_Hosts[j].pass[0] != 0)
               {
                  if (Options.logtofile) LogToFile_Collect(&Conn_Between_Hosts[j]);

                  if (!Options.quiet)
                  {
                     printf("\n\n%02d:%02d:%02d  %s:%d <--> %s:%d%15s\n\n", dd->tm_hour, dd->tm_min, dd->tm_sec,
                           Conn_Between_Hosts[j].source_ip,
                           Conn_Between_Hosts[j].source_port,
                           Conn_Between_Hosts[j].dest_ip,
                           Conn_Between_Hosts[j].dest_port,
                           Conn_Between_Hosts[j].type
                           );

                     printf("%s\n", Conn_Between_Hosts[j].user);
                     printf("%s\n", Conn_Between_Hosts[j].pass);
                     if (strlen(Conn_Between_Hosts[j].info))
                        printf("\n%s\n", Conn_Between_Hosts[j].info);
                  }
                  Decodedata_SetArrayIndex(&Conn_Between_Hosts[j], -1); // dont display in the future...
                  memset(&Conn_Between_Hosts[j].user, 0, sizeof(Conn_Between_Hosts[j].user));
                  memset(&Conn_Between_Hosts[j].pass, 0, sizeof(Conn_Between_Hosts[j].pass));
                  memset(&Conn_Between_Hosts[j].info, 0, sizeof(Conn_Between_Hosts[j].info));
                  #ifdef DEBUG
                     Debug_msg("\tConnection %d displayed and deleted...", j+1);
                  #endif
               }
            }  // end for
            TIME_FINISH;
            if (TIME_ELAPSED >= 300)
            {
               #ifdef DEBUG
                  Debug_msg("\tConnection List refreshed after %.0f minutes...", (TIME_ELAPSED)/60);
               #endif
               TIME_START;                         // after 300 seconds (5 min)...
               Decodedata_RefreshConnectionList(); // periodically refresh the list...
            }
            usleep(5000);
         }
         else // !collect
         {

            if (Options.logtofile) LogToFile(&data_from_illithid);
            if (!stop && !Options.quiet )
            {
               switch (view)
               {
                  case ASCII_VIEW:
                     printf("\n\n\n%02d:%02d:%02d  %s:%d --> %s:%d\n\n%s", dd->tm_hour, dd->tm_min, dd->tm_sec,
                        data_from_illithid.source_ip,
                        data_from_illithid.source_port,
                        data_from_illithid.dest_ip,
                        data_from_illithid.dest_port,
                        Decodedata_GetAsciiData(data_from_illithid.data, data_from_illithid.datasize)
                     );
                     break;

                  case TEXT_VIEW:
                     printf("\n\n\n%02d:%02d:%02d  %s:%d --> %s:%d\n\n%s", dd->tm_hour, dd->tm_min, dd->tm_sec,
                        data_from_illithid.source_ip,
                        data_from_illithid.source_port,
                        data_from_illithid.dest_ip,
                        data_from_illithid.dest_port,
                        Decodedata_GetTextData(data_from_illithid.data, data_from_illithid.datasize)
                     );
                     break;

                  case HEX_VIEW:
                     if (data_from_illithid.proto == 'T')
                        printf("\n\n%02d:%02d:%02d  %s:%d --> %s:%d | seq %lx ack %lx | flags %s |\n%s ", dd->tm_hour, dd->tm_min, dd->tm_sec,
                           data_from_illithid.source_ip,
                           data_from_illithid.source_port,
                           data_from_illithid.dest_ip,
                           data_from_illithid.dest_port,
                           data_from_illithid.seq,
                           data_from_illithid.ack_seq,
                           Decodedata_TCPFlags(data_from_illithid.flags),
                           Decodedata_GetHexData(data_from_illithid.data, data_from_illithid.datasize, 80)
                        );
                     else
                        printf("\n\n%02d:%02d:%02d  %s:%d --> %s:%d | UDP |\n%s ", dd->tm_hour, dd->tm_min, dd->tm_sec,
                           data_from_illithid.source_ip,
                           data_from_illithid.source_port,
                           data_from_illithid.dest_ip,
                           data_from_illithid.dest_port,
                           Decodedata_GetHexData(data_from_illithid.data, data_from_illithid.datasize, 80)
                        );
                     break;
               }
               fflush(stdout);
            }
         }
      }
      else
         usleep(1);
   }
}


void Simple_PassiveScan(void)
{
   pthread_t Dryad_pid;
   int i;
   fd_set msk_fd;
   struct timeval TimeOut;
   TIME_DECLARE;
   u_short passive_csum=0;

#ifdef DEBUG
   Debug_msg("Simple_PassiveScan");
#endif

   if (Options.quiet)  Simple_Demonize();

   if (!Options.quiet) printf("\nPress 'h' for help...\n\n");

   Dryad_pid = Dryad_Run();

   if (!Options.quiet) printf(" Passive Scanning : ANY <--> ANY\n\n");

   memset(&TimeOut, 0, sizeof(TimeOut));  //  timeout = 0
   FD_ZERO(&msk_fd);

   if(!Options.quiet)
   {
      #if defined (HAVE_TERMIOS_H) && !defined (CYGWIN)
         set_raw_term();   // non blocking stdin... yes this work !!
      #else
         #ifdef DEBUG
            Debug_msg("Simple_PassiveScan -- NO TERMIOS_H");
         #endif
         fcntl(0, F_SETFL, O_NONBLOCK);   // stdin non blocking... seems to be a non working method for me...
      #endif
   }

   TIME_START;

      loop
      {

         FD_SET(0, &msk_fd);

         select(FOPEN_MAX, &msk_fd, (fd_set *) 0, (fd_set *) 0, &TimeOut);

         if (FD_ISSET(0, &msk_fd))
         {
            char ch = 0;
            ch = getchar();
            switch(ch)
            {

               case 'L':
               case 'l':
                     printf("\n\nCollected infos dumped to %s\n\n", LogToFile_MakePassiveReport(ch));
                     break;

               case 'V':
               case 'v':
                     fprintf(stdout, "\n\n=================================================================\n");
                     fprintf(stdout, "                        ETTERCAP REPORT \n");
                     fprintf(stdout, "=================================================================\n");
                        for (i=0; i < number_of_passive_hosts; i++)
                        {
                           struct open_ports *current;

                           if (ch == 'v' && !strcmp(Passive_Host[i].type, "NL")) continue; // skip non local ip
                           fprintf(stdout, "\n=================================================================\n");
                           fprintf(stdout, "\n IP & MAC address    : %-15s%27s\n\n", Passive_Host[i].ip, Passive_Host[i].mac );
                           fprintf(stdout, " HOSTNAME            : %s\n\n", Inet_HostName(Passive_Host[i].ip));
                           if (!strcmp(Passive_Host[i].type, "GW")) fprintf(stdout, "**** THIS HOST IS A GATEWAY FOR IPs LIKE %s ****\n\n", Passive_Host[i].gwforthis);
                           if (!strcmp(Passive_Host[i].type, "RT")) fprintf(stdout, "**** THIS HOST ACTS AS A ROUTER FOR THE LAN ****\n\n");
                           if (!strcmp(Passive_Host[i].type, "NL")) fprintf(stdout, "**** THIS HOST DOESN'T BELONG TO THE NETMASK ****\n\n");
                           if (Passive_Host[i].os[0] == 0 && Passive_Host[i].os[1] != 0)
                           {
                              fprintf(stdout, " UNKNOWN FINGERPRINT : %s\n",  Passive_Host[i].fingerprint);
                              fprintf(stdout, " THE NEAREST IS      : %s\n\n", Passive_Host[i].os + 1);
                           }
                           else
                           {
                              fprintf(stdout, " FINGERPRINT         : %s\n\n",  Passive_Host[i].fingerprint);
                              fprintf(stdout, " OPERATING SYSTEM    : %s\n\n",  Passive_Host[i].os);
                           }
                           fprintf(stdout, " NETWORK ADAPTER     : %s\n\n",  Fingerprint_MAC(Passive_Host[i].mac));
                           fprintf(stdout, " DISTANCE IN HOP     : %d\n\n", Passive_Host[i].hop);
                           if (!LIST_EMPTY(&Passive_Host[i].tcp_ports))
                           {
                              LIST_FOREACH(current, &Passive_Host[i].tcp_ports, next)
                              {
                                 if (current == LIST_FIRST(&Passive_Host[i].tcp_ports))
                                    fprintf(stdout, " OPEN PORTS  (tcp)   : %-5d  %s\n", current->port, Decodedata_GetType('T', current->port, current->port) );
                                 else
                                    fprintf(stdout, "                     : %-5d  %s\n", current->port, Decodedata_GetType('T', current->port, current->port) );
                              }
                           }
                           else
                              fprintf(stdout, " OPEN PORTS  (tcp)   : NONE\n");

                           fprintf(stdout, "\n");

                           if (!LIST_EMPTY(&Passive_Host[i].udp_ports))
                           {
                              LIST_FOREACH(current, &Passive_Host[i].udp_ports, next)
                              {
                                 if (current == LIST_FIRST(&Passive_Host[i].udp_ports))
                                    fprintf(stdout, " OPEN PORTS  (udp)   : %-5d  %s\n", current->port, Decodedata_GetType('U', current->port, current->port) );
                                 else
                                    fprintf(stdout, "                     : %-5d  %s\n", current->port, Decodedata_GetType('U', current->port, current->port) );
                              }
                           }
                           else
                              fprintf(stdout, " OPEN PORTS  (udp)   : NONE\n");

                           fprintf(stdout, "\n");

                           if (!LIST_EMPTY(&Passive_Host[i].tcp_ports))
                           {
                              LIST_FOREACH(current, &Passive_Host[i].tcp_ports, next)
                              {
                                 if (!strlen(current->banner)) continue;
                                 if (current == LIST_FIRST(&Passive_Host[i].tcp_ports))
                                    fprintf(stdout, " TCP SERVICES BANNER : %-5d  %s\n", current->port, current->banner );
                                 else
                                    fprintf(stdout, "                     : %-5d  %s\n", current->port, current->banner );
                              }
                           }
                           fprintf(stdout, "\n=================================================================\n");
                        }
                     break;

               case 'H':
               case 'h':
                     printf("\n\n[qQ]  - quit\n");
                     printf(    "[l ]  - dump the local report to a file\n");
                     printf(    "[L ]  - dump the FULL report to a file\n");
                     printf(    "[v ]  - view the local report\n");
                     printf(    "[V ]  - view the FULL report\n\n");
                     break;

               case 'Q':
               case 'q':
#if defined (HAVE_TERMIOS_H) && !defined (CYGWIN)
                     if(!Options.quiet) reset_term();
#endif
                     printf("\n\n\nShutting down all threads... ");
                     fflush(stdout);
                     ECThread_destroy(Dryad_pid);
                     Decodedata_FreePassiveList();
                     printf("Done.\n\n");
                     exit(0);
                     break;
            }
         }

         if (Options.logtofile)
         {
            TIME_FINISH;
            if (TIME_ELAPSED >= 300)
            {
               #ifdef DEBUG
                  Debug_msg("\tCollected infos saved after %.0f minutes...", (TIME_ELAPSED)/60);
               #endif
               if (!Options.quiet) printf("\tCollected infos saved after %.0f minutes..." ,(TIME_ELAPSED)/60);
               TIME_START;                       // after 300 seconds (5 min)...
               LogToFile_MakePassiveReport('l'); // periodically save the list...
            }
         }

         if (!Options.quiet)
         {
            u_short hash = Inet_Forge_Checksum((u_short *)Passive_Host, 0xe77e, sizeof(PASSIVE_DATA)*number_of_passive_hosts, 0, 0);

            if (passive_csum != hash && number_of_passive_hosts > 0)
            {
               int j;

               Decodedata_Passive_SortList();
               printf ("\n\n>>> PASSIVE INFORMATION <<<\n\n");
               for(j=0; j< number_of_passive_hosts; j++)
               {
                  printf(" --> %15s : %2s : %s\n", Passive_Host[j].ip, Passive_Host[j].type, Passive_Host[j].os);
               }
               passive_csum = hash;
            }
         }
         usleep(1);
      }
}


/* EOF */
