/*
    ettercap -- a ncurses-based sniffer/interceptor utility for switched LAN

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

    $Id: ec_main.c,v 1.17 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#include <sys/ioctl.h>
#if defined (HAVE_TERMIOS_H) && !defined (CYGWIN)
   #include <termios.h>
#endif
#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include "missing/getopt.h"
#endif


#include "include/ec_error.h"
#include "include/ec_inet.h"
#include "include/ec_simple.h"
#include "include/ec_signal.h"
#include "include/ec_parser.h"
#include "include/ec_filterdrop.h"
#include "include/ec_thread.h"
#include "include/ec_plugins.h"

#ifdef HAVE_NCURSES
    #include "include/ec_interface.h"
#endif

// global variables

HOST *Host_In_LAN = NULL;              // ec_main.h
int number_of_hosts_in_lan;

CONNECTION *Conn_Between_Hosts = NULL; // ec_main.h
int number_of_connections = -1;

PASSIVE_DATA *Passive_Host;            // ec_main.h
int number_of_passive_hosts;

CURRENT_SNIFFED_DATA current_illithid_data;

HOST Host_Source;
HOST Host_Dest;

char **Host_List;          // scan only these hosts
int host_to_be_scanned;

char *Execute_Plugin;

OPTIONS Options;

int pipe_with_illithid_data = -1;
int pipe_with_plugins = -1;
int pipe_inject[2];
int pipe_kill[2];

char active_dissector = 1;    // ec_main.h
char filter_on_source = 0;
char filter_on_dest = 0;


// protos...

void Main_Usage(void);
void Main_Interactive(void);
void Main_Normal(void);
void Main_CheckForRun(char *program_argv0);
void Main_CheckForFilters(void);
void Main_ParseParameters(char *first, char *second, char *third, char *fourth);
void Main_Check_NewRelease(void);
#if DEVEL_RELEASE == 1
void Main_Devel_Release(void);
#endif
//-----------------------------------

int main(int argc, char *argv[])
{

#ifdef DEBUG
   Debug_Init();
   Debug_msg("Main");
#endif

   ECThread_register(pthread_self(), "ettercap");

   Main_CheckForRun(argv[0]);     // it is ok ?

   Signal_SigBuster();     // signal masking

#if DEVEL_RELEASE == 1
   Main_Devel_Release();
#endif

#ifdef DEBUG
{
   int i;
   for(i=0; i<argc; i++)
      Debug_msg("Main_ParameterList - [%d] %s", i, argv[i]);
}
#endif

   Options.delay = DEFAULT_DELAY;               // the default delay between arp replies (ec_doppleganger)
   Options.storm_delay = DEFAULT_STORM_DELAY;   // the default delay between arp request on start up (ec_inet)


   if (Parser_ParseOptions(argc, argv) == 1)    // config file
      Parser_ParseConfFile(optarg);

   if (Options.version)
      Main_Check_NewRelease();

   if (!strcmp(Options.netiface, ""))        // set the default interface
   {
      if (Inet_FindIFace(Options.netiface) == -1)
         Error_msg("No suitable Network Interface found !!");
   }
   else if ( Inet_CorrectIface(Options.netiface) < 0)
#ifdef LINUX
      Error_msg("%s (%s)", strerror(errno), Options.netiface);
#else
      Error_msg("Network Interface %s is NOT valid !!", Options.netiface);
#endif

   if (Options.filter) Main_CheckForFilters();

   pipe(pipe_inject);      // create the pipes with illithid
   pipe(pipe_kill);

   if (Options.normal)
      Main_Normal();
   else
      Main_Interactive();

return 0;
}




void Main_Usage(void)
{

#ifdef DEBUG
   Debug_msg("Main_Usage");
#endif

   fprintf (stdout, "\n\033[01m\033[1m%s %s (c) 2001 %s\033[0m\n\n", PROGRAM, VERSION, AUTHORS);
   fprintf (stdout, "\nUsage: %s [OPTION] [HOST:PORT] [HOST:PORT] [MAC] [MAC]\n\n", PROGRAM);

   fprintf (stdout, "Sniffing method:\n");
   fprintf (stdout, "  -a, --arpsniff               ARPBASED sniffing (specifying two host)\n");
   fprintf (stdout, "                               SMARTARP (specifying one host but with the list)\n");
   fprintf (stdout, "                               PUBLICARP (specifying only one host silently)\n");
   fprintf (stdout, "                               in silent mode : must specify both IP and MAC\n");
   fprintf (stdout, "                                 i.e.: ettercap -Nza IP IP MAC MAC    (ARPBASED)\n");
   fprintf (stdout, "                                       ettercap -Na IP MAC           (SMARTCARP)\n");
   fprintf (stdout, "                                       ettercap -Nza IP MAC          (PUBLICARP)\n");
   fprintf (stdout, "  -s, --sniff                  IPBASED sniffing\n");
   fprintf (stdout, "                               you can specify the ANY ip that means ALL hosts\n");
   fprintf (stdout, "                                 e.g.: ettercap -Nzs ANY:80  (sniff only http)\n");
   fprintf (stdout, "  -m, --macsniff               MACBASED sniffing \n");
   fprintf (stdout, "                                 e.g.: ettercap -zm MAC1 MAC2\n");
   fprintf (stdout, "                                       ettercap -Nm MAC\n");

   fprintf (stdout, "\nGeneral options:\n");
   fprintf (stdout, "  -N, --simple                 NON interactive mode (without ncurses)\n");
   fprintf (stdout, "  -z, --silent                 silent mode (no arp storm on start up)\n");
   fprintf (stdout, "  -O, --passive                passive scanning of the LAN\n");
   fprintf (stdout, "  -b, --broadping              broadcast ping instead of arp storm on start up\n");
   fprintf (stdout, "  -D, --delay <n sec>          the dalay between arp replies (default is 30 sec)\n");
   fprintf (stdout, "  -Z, --stormdelay <n usec>    the dalay between arp request (def is 1500 usec)\n");
   fprintf (stdout, "  -S, --spoof <IP>             on start up send request with this IP\n");
   fprintf (stdout, "  -H, --hosts <IP1[,IP2][,..]> on start up scan only these hosts\n");
   fprintf (stdout, "  -d, --dontresolve            don't resolve the IPs (speed up the startup)\n");
   fprintf (stdout, "  -i, --iface <iface>          network interface to be used\n");
   fprintf (stdout, "  -n, --netmask <netmask>      the netmask used to scan the lan\n");
   fprintf (stdout, "  -e, --etterconf <filename>   load options from a config file\n");
   fprintf (stdout, "  -j, --loadhosts <filename>   load hosts list from a file\n");
   fprintf (stdout, "  -k, --savehosts              save hosts list to a file\n");
   fprintf (stdout, "  -v, --version                check for the latest ettercap version\n");
   fprintf (stdout, "  -y, --yes                    in combination with -v auto answer yes\n");
   fprintf (stdout, "  -h, --help                   this help screen\n");

   fprintf (stdout, "\nSilent mode options (combined with -N):\n");
   fprintf (stdout, "  -u, --udp                    sniff only udp connection (default is tcp)\n");
   fprintf (stdout, "  -R, --reverse                sniff all the connection but the selected one\n");
#ifdef PERMIT_PLUGINS
   fprintf (stdout, "  -p, --plugin <name>          run the \"name\" plugin (\"list\" for available ones)\n");
#endif
   fprintf (stdout, "  -l, --list                   list all hosts in the lan\n");
   fprintf (stdout, "  -C, --collect                collect users and passwords only\n");
   fprintf (stdout, "                               this options must be used with a sniffing method\n");
   fprintf (stdout, "                                    Eg: ettercap -NCzs\n");
   fprintf (stdout, "  -f, --fingerprint <host>     do OS fingerprinting on HOST\n");
   fprintf (stdout, "  -x, --hexview                display data in hex mode\n");
   fprintf (stdout, "  -L, --logtofile              logs all data to specific file(s)\n");
   fprintf (stdout, "  -q, --quiet                  \"demonize\" ettercap (useful with -L)\n");
   fprintf (stdout, "  -w, --newcert                create a new SSL cert file for HTTPS dissector\n");
   fprintf (stdout, "  -F, --filter <filename>      load  \"filename\" as the filter chain file\n");
   fprintf (stdout, "  -c, --check                  check for other poisoners in the LAN\n");
   fprintf (stdout, "  -t, --linktype               tries to indentify the LAN type (switch or hub)\n");
   fprintf (stdout, "\n");

   exit (0);
}



void Main_Interactive(void)
{
#ifdef HAVE_NCURSES

#ifndef CYGWIN
   struct winsize  ws = {0, 0, 0, 0};

   #ifdef DEBUG
      Debug_msg("Main_Interactive");
   #endif

#endif

#ifndef CYGWIN
   if ( ioctl(0, TIOCGWINSZ, &ws) < 0)          // syscall for the window size
      Error_msg("ec_main:%d ioctl(TIOCGWINSZ) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if ( (ws.ws_row < 25) || (ws.ws_col < 80) )
   {
      char *p;
      short cols = ws.ws_col;
      short rows = ws.ws_row;

      #ifdef DEBUG
         Debug_msg("Main_Interactive -- screen wide %dx%d (TIOCGWINSZ)", ws.ws_row, ws.ws_col);
      #endif

      if ((p = getenv("LINES")))
         rows = atoi(p);
      if ((p = getenv("COLUMNS")))
         cols = atoi(p);

      #ifdef DEBUG
         Debug_msg("Main_Interactive -- screen wide %sx%s (getenv)", getenv("LINES"), getenv("COLUMNS"));
      #endif

      if (rows < 25 || cols < 80)
         Error_msg("Screen must be at least 25x80 !!");

   }
#endif

#ifdef PERMIT_PLUGINS
   Plugin_LoadAll();
#endif

   if (!Options.silent) printf("Building host list for netmask %s, please wait...\n", Inet_MySubnet());
   number_of_hosts_in_lan = Inet_HostInLAN();

   Interface_InitTitle(Host_In_LAN[0].ip, Host_In_LAN[0].mac, Inet_MySubnet());
   Interface_InitScreen();
   Interface_Run();
#else
   #ifdef DEBUG
      Debug_msg("Ncurses not supported -- turning to non interactive mode...");
   #endif
   fprintf(stdout, "\nNcurses not supported -- turning to non interactive mode...\n\n");
   Main_Normal();
#endif

#ifdef DEBUG
   Debug_msg("Main_Interactive_END");
#endif
}




void Main_Normal(void)
{

#ifdef DEBUG
   Debug_msg("Main_Normal");
#endif

   printf ("\n\033[01m\033[1m%s %s (c) 2001 %s\033[0m\n\n", PROGRAM, VERSION, AUTHORS);
   printf ("Your IP: %s with MAC: %s on Iface: %s\n", Inet_MyIPAddress(), Inet_MyMACAddress(), Options.netiface);

#ifdef PERMIT_PLUGINS
   if (Options.plugin || Options.arpsniff || Options.sniff  || Options.macsniff)
      Plugin_LoadAll();
#endif

   if (Options.list || Options.check || Options.arpsniff ||
       Options.sniff  || Options.macsniff || Options.link ||
       Options.passive || Options.hoststofile)
   {
      if (!Options.silent) printf("Building host list for netmask %s, please wait...\n", Inet_MySubnet());
      number_of_hosts_in_lan = Inet_HostInLAN();
   }

   if (Options.hoststofile)
   {
      fprintf(stdout, "\nHost list dumped into file: %s\n\n", Inet_Save_Host_List());
      exit(0);
   }

   if (Options.list)
      Simple_HostList();

   if (Options.check)
      Simple_CheckForPoisoner();

   if (Options.link)
      Simple_CheckForSwitch();

   if (Options.finger)
      Simple_FingerPrint();

#ifdef PERMIT_PLUGINS
   if (Options.plugin)
      Simple_Plugin();
#endif

   if (Options.arpsniff || Options.sniff  || Options.macsniff)
      Simple_Run();

   if (Options.passive)
      Simple_PassiveScan();

   printf("\n");
#ifdef DEBUG
   Debug_msg("Main_Normal_END");
#endif

exit(0);
}



void Main_CheckForRun(char *program_argv0)
{

#ifdef DEBUG
   Debug_msg("Main_CheckForRun");
#endif

   if (getuid() != 0)
   {
      Options.normal = 1;
      Error_msg("Sorry UID %d, must be root to run %s !!", getuid(), PROGRAM);
   }

   if (!strstr(program_argv0, PROGRAM))      // just for script-kiddies ;)
      Error_msg("ehi guy ! my name is \"%s\" ! I really don't like \"%s\"...", PROGRAM, program_argv0);

}



void Main_CheckForFilters(void)
{

#ifdef DEBUG
   Debug_msg("Main_CheckForFilters");
#endif

   switch(FilterDrop_Validation(Filter_Array_Dest))
   {
      case 1:
         fprintf(stdout, "CAUTION: the source filter chain contains a loop...\n");
         fprintf(stdout, "ettercap may hang up. please review your filter chain...  [press RETURN to continue]\n\n");
         getchar();
         break;
      case 2:
         Error_msg("CAUTION: a filter in the source chain has a jump outside the chain !!!\n"
                   "ettercap will sig fault. review your filter chain immediately !!\n\n");
         break;
   }
   switch( FilterDrop_Validation(Filter_Array_Dest))
   {
      case 1:
         fprintf(stdout, "CAUTION: the dest filter chain contains a loop...\n");
         fprintf(stdout, "ettercap may hang up. please review your filter chain...  [press RETURN to continue]\n\n");
         getchar();
         break;
      case 2:
         Error_msg("CAUTION: a filter in the dest chain has a jump outside the chain !!!\n"
                   "ettercap will sig fault. review your filter chain immediately !!\n\n");
         break;
   }

}



#if DEVEL_RELEASE == 1
void Main_Devel_Release(void)
{

   fprintf (stdout, "\n\n");
   fprintf (stdout, "==============================================================================\n");
   fprintf (stdout, "  %s %s IS STILL IN DEVELOPMENT STATE. ABSOLUTELY NO WARRANTY !\n\n", PROGRAM, VERSION);
   fprintf (stdout, "  if you are a betatester please report bugs to :\n");
   fprintf (stdout, "      http://ettercap.sourceforge.net/forum/viewforum.php?forum=7\n\n");
   fprintf (stdout, "  or send an email to:\n");
   fprintf (stdout, "      alor@users.sourceforge.net\n");
   fprintf (stdout, "      crwm@freemail.it\n\n");
//   fprintf (stdout, "  if you are NOT a betatester, I don't know where you downloaded this release\n");
//   fprintf (stdout, "  but this is NOT for you, so don't blame us for any bugs or problems !\n");
   fprintf (stdout, "==============================================================================\n");
   fprintf (stdout, "\n\n");
// if (!Options.normal)
// {
//    fprintf(stdout, "Press return to continue...");
//    getchar();
// }
}
#endif


void Main_Check_NewRelease(void)
{
   char answer;
   socket_handle sock;
   char *ptr;
   char *latest;
   char getmsg[512];
   char buffer[4096];
   char host[] = "ettercap.sourceforge.net";
   char page[] = "/latest.php";
//   char host[] = "zefiro.alor.org";
//   char page[] = "/ettercap/latest.php";

#ifdef DEBUG
   Debug_msg("Main_Check_NewRelease -- now is %s", VERSION);
#endif

   memset(buffer, 0, sizeof(buffer));

   fprintf (stdout, "\nCurrent version is : \033[01m\033[1m%s\033[0m\n", VERSION);

   if (!Options.yes)
   {
      fprintf (stdout, "\n\nDo you want to check for the latest version ? (y/n) ");
      fflush(stdout);
      fflush(stdin);
      answer = getchar();
   }
   else
      answer = 'y';

   fprintf(stdout, "\n\n");

   if (answer == 'y' || answer == 'Y')
   {
      fprintf (stdout, "Connecting to http://%s...\n", host);
      sock = Inet_OpenSocket(host, 80);

      fprintf (stdout, "Requesting %s...\n\n", page);
      snprintf(getmsg, sizeof(getmsg), "GET %s HTTP/1.0\r\n"
                                       "Host: %s\r\n"
                                       "User-Agent: %s (%s).\r\n"
                                       "\r\n", page, host, PROGRAM, VERSION );
      Inet_Http_Send(sock, getmsg);

#ifdef DEBUG
   Debug_msg("Main_Check_NewRelease - SEND -----------------------\n\n%s\n\n", getmsg);
   Debug_msg("Main_Check_NewRelease - ENDSEND --------------------");
#endif

      Inet_Http_Receive(sock, buffer, sizeof(buffer));

#ifdef DEBUG
   Debug_msg("Main_Check_NewRelease - RECEIVE --------------------\n\n%s\n\n", buffer);
   Debug_msg("Main_Check_NewRelease - ENDRECEIVE -----------------");
#endif

      Inet_CloseSocket(sock);

      if (!strlen(buffer))
         Error_msg("The server didn't replied");

      ptr = strstr(buffer, "\r\n\r\n") + 4;  // skip the headers.
      if (strncmp(ptr, "LATEST: ", 8))
         Error_msg("Error parsing the response... \n\n");

      ptr +=8;
      latest = strdup(strtok(ptr, "\n"));
      if ( strncmp(latest, VERSION, 5) == 0)
         Error_msg("You already have the latest ettercap release (\033[01m\033[1m%s\033[0m)\n\n", latest);
      else if (strncmp(latest, VERSION, 5) < 0)
      {
         #ifdef DEBUG
            Debug_msg("You have a newer release than the official one (%s)", latest);
         #endif
         fprintf(stdout, "You have a newer release (\033[01m\033[1m%s\033[0m) than the official one (\033[01m\033[1m%s\033[0m)\n\n", VERSION, latest);
         fprintf(stdout, "\033[01m\033[1m%s\033[0m is currently under development... use at you own risk... ;)\n\n", VERSION);
         exit(0);
      }
      else
      {
         fprintf(stdout, "The latest release is \033[01m\033[1m%s\033[0m\n\n", latest);
         ptr += 6;
         fprintf(stdout, "NEW in this release:\n%s\n\n", ptr);
         if (!Options.yes)
         {
            fprintf(stdout, "Do you want to wget it ? (y/n)");
            fflush(stdout);
            fflush(stdin);
            while ( (answer = getchar()) == '\n');
         }
         else
            answer = 'y';

         fprintf(stdout, "\n\n");

         if (answer == 'y' || answer == 'Y')
         {
            char wget[100];
            snprintf(wget, sizeof(wget), "http://%s/download/ettercap-%s.tar.gz", host, latest);
            if ( execl( WGET_PATH, "wget", wget, NULL) == -1 )
               Error_msg("Cannot execute wget ! Auto update cannot download the file...\n");
         }
      }
   }
   exit(0);
}


/* EOF */


