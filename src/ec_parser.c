/*
    ettercap -- parsing utilities

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

    $Id: ec_parser.c,v 1.16 2001/12/20 20:09:45 alor Exp $
*/


#include "include/ec_main.h"

#include <ctype.h>
#ifdef HAVE_GETOPT_H
   #include <getopt.h>
#else
   #include "missing/getopt.h"
#endif

#include "include/ec_error.h"
#include "include/ec_inet.h"
#include "include/ec_simple.h"
#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_filterdrop.h"

extern char *Execute_Plugin;

char *list_to_parse;    // host list expanded from wildcards
char *loading_plugs;    // list of plugin to be loaded.  it has this form: "|dummy|foo|bar|..."

// protos...

extern void Main_Usage(void);
void Parser_ParseConfFile(char *filename);
void Parser_Dissectors(char *toparse);
void Parser_Plugins(char *toparse);
char Parser_Activated_Plugin(char *name);
void Parser_ParseParameters(char *first, char *second, char *third, char *fourth);
int Parser_ParseOptions(int counter, char **values);
char * Parser_PrintFilter(DROP_FILTER *ptr, int i);
void Parser_LoadFilters(char *filename);
int Parser_HostList(char *to_parse);
char * Parser_AddStr(char *list, char *string);
void Parser_Expand(char *to_parse);
int match_pattern(const char *s, const char *pattern);
void Parser_Filters(char *line, DROP_FILTER *filter);
char *Parser_StrSpacetoUnder(char *h_name);

//-----------------------------------


int Parser_ParseOptions(int counter, char **values)
{
   int c;

   static struct option long_options[] = {
      { "help", no_argument, NULL, 'h' },
      { "version", no_argument, NULL, 'v' },
      { "simple", no_argument, NULL, 'N' },
      { "list", no_argument, NULL, 'l' },
      { "arpsniff", no_argument, NULL, 'a' },
      { "sniff", no_argument, NULL, 's' },
      { "macsniff", no_argument, NULL, 'm' },
      { "iface", required_argument, NULL, 'i' },
      { "netmask", required_argument, NULL, 'n' },
      { "check", no_argument, NULL, 'c' },
      { "plugin", required_argument, NULL, 'p' },
      { "hexview", no_argument, NULL, 'x' },
      { "silent", no_argument, NULL, 'z' },
      { "udp", no_argument, NULL, 'u' },
      { "fingerprint", no_argument, NULL, 'f' },
      { "linktype", no_argument, NULL, 't' },
      { "collect", no_argument, NULL, 'C' },
      { "broadping", no_argument, NULL, 'b' },
      { "logtofile", no_argument, NULL, 'L' },
      { "quiet", no_argument, NULL, 'q' },
      { "etterconf", required_argument, NULL, 'e' },
      { "dontresolve", no_argument, NULL, 'd' },
      { "newcert", no_argument, NULL, 'w' },
      { "filter", required_argument, NULL, 'F' },
      { "hosts", required_argument, NULL, 'H' },
      { "yes", no_argument, NULL, 'y' },
      { "delay", required_argument, NULL, 'D' },
      { "reverse", no_argument, NULL, 'R' },
      { "spoof", required_argument, NULL, 'S' },
      { "stormdelay", required_argument, NULL, 'Z' },
      { "passive", no_argument, NULL, 'O' },
      { "loadhosts", required_argument, NULL, 'j' },
      { "savehosts", no_argument, NULL, 'k' },
      { 0 , 0 , 0 , 0}
   };

#ifdef DEBUG
   Debug_msg("Parser_ParseOptions -- [%d] [%s]", counter, *values);
#endif

   optind = 0;

#ifdef PERMIT_PLUGINS
   while ((c = getopt_long (counter, values, "hvyNlasmci:p:xzuftCbn:Lqe:dwF:H:D:RS:Z:Oj:k",long_options, (int *)0)) != EOF) {
#else
   while ((c = getopt_long (counter, values, "hvyNlasmci:xzuftCbn:Lqe:dwF:H:D:RS:Z:Oj:k",long_options, (int *)0)) != EOF) {    // no plugin
#endif

      switch (c) {

         case 'h':
            Main_Usage();
         break;

         case 'v':   Options.version = 1;
                     Options.normal = 1;        break;

         case 'y':   Options.yes = 1;           break;

         case 'N':   Options.normal = 1;        break;

         case 'l':   Options.list = 1;          break;

         case 'a':   Options.arpsniff = 1;      break;

         case 's':   Options.sniff = 1;         break;

         case 'm':   Options.macsniff = 1;      break;

         case 'c':   Options.check = 1;         break;

         case 'x':   Options.hexview = 1;       break;

         case 'z':   Options.silent = 1;        break;

         case 'u':   Options.udp = 1;           break;

         case 'f':   Options.finger = 1;        break;

         case 't':   Options.link = 1;          break;

         case 'C':   Options.collect = 1;       break;

         case 'b':   Options.broadping = 1;     break;

         case 'L':   Options.logtofile = 1;     break;

         case 'q':   Options.quiet = 1;         break;

         case 'd':   Options.dontresolve = 1;   break;

         case 'R':   Options.reverse = 1;       break;

         case 'O':   Options.passive = 1;
                     Options.silent = 1;        break;

#ifdef PERMIT_PLUGINS
         case 'p':
            Options.plugin = 1;
            Execute_Plugin = strdup(optarg);
         break;
#endif

         case 'i':
            strlcpy(Options.netiface, optarg, sizeof(Options.netiface));
         break;

         case 'j':
            Options.hostsfromfile = 1;
            Options.hostfile = strdup(optarg);
         break;

         case 'k':
            Options.hoststofile = 1;
         break;

         case 'n':
            strlcpy(Options.netmask, optarg, sizeof(Options.netmask));
         break;

         case 'D':
            Options.delay = atoi(optarg);
            if (Options.delay == 0) Options.delay = 1;      // at least one second...
         break;

         case 'Z':
            Options.storm_delay = atoi(optarg);
            if (Options.storm_delay == 0) Options.storm_delay = 1;      // at least one usec...
         break;

         case 'S':
            Options.spoofIp = inet_addr(optarg);
         break;

         case 'e':
            if (!strcmp(values[0], "etter.conf"))
               Error_msg("You can't specify the --etterconf option in the conf file !! (safe exit avoiding loops)");
            else
               return 1;
         break;

         case 'w':
            Options.normal = 1;
            Simple_CreateCertFile();
         break;

         case 'F':
            filter_on_source = 1;
            filter_on_dest = 1;
            Parser_LoadFilters(optarg);
            Options.filter = 1;
         break;

         case 'H':
            host_to_be_scanned = Parser_HostList(optarg);
         break;

         case ':': // missing parameter
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", PROGRAM);
            exit(0);
         break;

         case '?': // unknown option
            fprintf(stdout, "\nTry `%s --help' for more options.\n\n", PROGRAM);
            exit(0);
         break;
      }
   }

   Parser_ParseParameters(values[optind], values[optind+1], values[optind+2], values[optind+3]);

   return 0;
}


void Parser_ParseParameters(char *first, char *second, char *third, char *fourth)
{

#ifdef DEBUG
   if (first)  Debug_msg("Parser_ParseParameters -- 1 [%s]", first); else goto exit_debug;
   if (second) Debug_msg("Parser_ParseParameters -- 2 [%s]", second); else goto exit_debug;
   if (third)  Debug_msg("Parser_ParseParameters -- 3 [%s]", third); else goto exit_debug;
   if (fourth) Debug_msg("Parser_ParseParameters -- 4 [%s]", fourth); else goto exit_debug;
exit_debug:
#endif

#define R(a,b,c) (a & b) | ((a ^ b) & c)     // returns true if more than one was selected

   if (!Options.normal) Options.reverse = 0;

   if (Options.quiet && !Options.normal && !Options.logtofile )
      Error_msg("Demonization is only useful with -NL or -NLC !!\n\n");

   if ( R(Options.arpsniff, Options.sniff, Options.macsniff) )
      Error_msg("Please select only one sniffing method !!\n\n");

   if (Options.silent && Options.broadping)
      Error_msg("Please select only one start up method !!\n\n");

   if (Options.collect && !(Options.sniff || Options.arpsniff || Options.macsniff))
      Error_msg("Please select one sniffing method to be used for collecting password !!\n\n");

   if (Options.normal && Options.passive && (Options.sniff || Options.arpsniff || Options.macsniff))
      Error_msg("Passive scanning can't be combined with a sniffing method !!\n\n");

   if (Options.sniff || Options.macsniff)
      Options.silent = 1;

   if (Options.silent)
   {
      if (Options.macsniff)
      {
         char check[6];

         if (first)
         {
            sscanf(first, "%17s", Host_Dest.mac);
            if (second)
               sscanf(second, "%17s", Host_Source.mac);
         }

         if ( strcmp(Host_Dest.mac, "") && Inet_GetMACfromString(Host_Dest.mac, check ) == -1)   // check for valid mac
            Error_msg("Incorrect parsing of MAC [%s] !!\nIt must be in the form 01:02:03:04:05:06 !!", Host_Dest.mac);
         if ( strcmp(Host_Source.mac, "") && Inet_GetMACfromString(Host_Source.mac, check ) == -1)   // check for valid mac
            Error_msg("Incorrect parsing of MAC [%s] !!\nIt must be in the form 01:02:03:04:05:06 !!", Host_Source.mac);
         if ( !strcmp(Host_Source.mac, Host_Dest.mac) && strcmp(Host_Source.mac, ""))
            Error_msg("SOURCE and DEST MAC address must be different !!");
      }

      if (Options.arpsniff)
      {
         int i=0;
         char check[6];

         if (first)
         {
            i++;
            sscanf(first, "%128[^:]:%d", Host_Dest.name, &Host_Dest.port);
            if (second)
            {
               i++;
               sscanf(second, "%128[^:]:%d", Host_Source.name, &Host_Source.port);
               if (third)
               {
                  i++;
                  sscanf(third, "%17s", Host_Dest.mac);
                  if (fourth)
                  {
                     i++;
                     sscanf(fourth, "%17s", Host_Source.mac);
                  }
               }
            }
         }
         if (i == 2)       // PUBLIC ARP
         {
            sscanf(second, "%17s", Host_Dest.mac);    // rescan the second parameter
            Host_Source.port = 0;
            strcpy(Host_Source.name, "");
            strcpy(Host_Source.ip, "");
            Host_Source.port = 0;

            if (Inet_GetMACfromString(Host_Dest.mac, check ) == -1)   // check for valid mac
               Error_msg("Incorrect parsing of MAC [%s] !!\nIt must be in the form 01:02:03:04:05:06 !!", Host_Dest.mac);
         }
         else if (i == 4)  // ARP BASED
         {
            if (Inet_GetMACfromString(Host_Dest.mac, check ) == -1)   // check for valid mac
               Error_msg("Incorrect parsing of MAC [%s] !!\nIt must be in the form 01:02:03:04:05:06 !!", Host_Dest.mac);
            if (Inet_GetMACfromString(Host_Source.mac, check ) == -1)   // check for valid mac
               Error_msg("Incorrect parsing of MAC [%s] !!\nIt must be in the form 01:02:03:04:05:06 !!", Host_Source.mac);
         }
         else
            Error_msg("Please specify both source and destination IP and MAC for ARP Based (full-duplex)\n"
                      "or only one IP and MAC for PUBLIC ARP (half-duplex)");

         if ( !strcmp(Host_Source.ip, Host_Dest.ip) && strcmp(Host_Source.ip, "") )
            Error_msg("SOURCE and DEST IP address must be different !!");
         if ( !strcmp(Host_Source.mac, Host_Dest.mac) && strcmp(Host_Source.mac, ""))
            Error_msg("SOURCE and DEST MAC address must be different !!");

      }

      if (Options.sniff || Options.plugin)
      {
         if (first)
         {
            sscanf(first, "%128[^:]:%d", Host_Dest.name, &Host_Dest.port);
            if (second) sscanf(second, "%128[^:]:%d", Host_Source.name, &Host_Source.port);

            if (!strcasecmp(Host_Source.name, "ANY") || !strcmp(Host_Source.name, "0") )
               strcpy(Host_Source.name, "");

            if (!strcasecmp(Host_Dest.name, "ANY") || !strcmp(Host_Dest.name, "0") )
               strcpy(Host_Dest.name, "");

            if ( !strcmp(Host_Source.name, Host_Dest.name) && strcmp(Host_Source.name, "") )
               Error_msg("SOURCE and DEST IP address must be different !!");
         }
      }

      if (Options.check)   Error_msg("You can't check for poisoners in silent mode !!");

      if (Options.list)    Error_msg("You can't make the list in silent mode !!");
   }
   else // !silent
   {
      if (Options.arpsniff && !first)
         Error_msg("Please specify  source and destination IP for ARP Based (full-duplex)\n"
                   "or only one IP for PUBLIC ARP (half-duplex)");

      if (first)
      {
         sscanf(first, "%128[^:]:%d", Host_Dest.name, &Host_Dest.port);
         if (second)
         {
            char check[6];
            if (Inet_GetMACfromString(second, check ) == -1)   // if it is a mac take it in dest, else it is the source ip
               sscanf(second, "%128[^:]:%d", Host_Source.name, &Host_Source.port);
            else
               sscanf(second, "%17s", Host_Dest.mac);
         }
      }
   }

   if (strcmp(Host_Source.name, ""))
      strcpy(Host_Source.ip, Inet_NameToIp(Host_Source.name));

   if (strcmp(Host_Dest.name, ""))
      strcpy(Host_Dest.ip, Inet_NameToIp(Host_Dest.name));



#ifdef DEBUG
   Debug_msg("Parser_ParseParameters - name - [%s][%s]", Host_Dest.name, Host_Source.name);
   Debug_msg("Parser_ParseParameters -  IP  - [%s][%s]", Host_Dest.ip, Host_Source.ip);
   Debug_msg("Parser_ParseParameters - port - [%d][%d]", Host_Dest.port, Host_Source.port);
   Debug_msg("Parser_ParseParameters -  MAC - [%s][%s]", Host_Dest.mac, Host_Source.mac);
#endif

}



char * Parser_AddStr(char *list, char *string)
{
	int len = strlen(list)+strlen(string)+1;

   list = realloc(list, len);
   if (list == NULL)
      ERROR_MSG("realloc()");
   strlcat(list, string, len);

   return list;
}



void Parser_ParseConfFile(char *filename)
{

   FILE *etterconf;
   char line[1024];
   char *to_be_parsed = NULL;
   char *option = NULL;
   char *ptr;
   int pargc = 0;
   char *pargv[256];
   char dissectors = 0;
#ifdef PERMIT_PLUGINS
   char plugins = 0;
#endif

#ifdef DEBUG
   Debug_msg("Parser_ParseConfFile - %s", filename);
#endif

   memset(&pargv, 0, 256*sizeof(int));

   fprintf (stdout, "Loading options from %s...\n", filename);

   to_be_parsed = calloc(1, 1);
   to_be_parsed = Parser_AddStr(to_be_parsed, "etter.conf ");

   etterconf = fopen(filename, "r");
   if (etterconf == NULL)
      ERROR_MSG("fopen()");

   do
   {
      fgets(line, 100, etterconf);
      if ( (ptr = strchr(line, '#')) )
         *ptr = 0;

      if ( (ptr = strchr(line, '\n')) )
         *ptr = 0;

      if (!strlen(line))   // skip 0 length line
         continue;

      #ifdef DEBUG
         Debug_msg("Parser_ParseConfFile - [%s]", line);
      #endif

      if (!strncasecmp(line, "OPTIONS: ", 9))
      {
         option = strdup(strchr(line, '-'));
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "IFACE: ", 7))
      {
         option = strdup(line+7);
         to_be_parsed = Parser_AddStr(to_be_parsed, " --iface ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "NETMASK: ", 9))
      {
         option = strdup(line+9);
         to_be_parsed = Parser_AddStr(to_be_parsed, " --netmask ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "DELAY: ", 7))
      {
         option = strdup(line+7);
         to_be_parsed = Parser_AddStr(to_be_parsed, " --delay ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "HOSTS: ", 7))
      {
         option = strdup(line+7);
         to_be_parsed = Parser_AddStr(to_be_parsed, " --hosts ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

#ifdef PERMIT_PLUGINS
      if (!strncasecmp(line, "PLUGIN: ", 8))
      {
         option = strdup(line+8);
         to_be_parsed = Parser_AddStr(to_be_parsed, " --plugin ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }
#endif

      if (!strncasecmp(line, "FILTER: ", 8))
      {
         option = strdup(line+8);
         to_be_parsed = Parser_AddStr(to_be_parsed, " --filter ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "IP1: ", 5))
      {
         option = strdup(line+5);
         to_be_parsed = Parser_AddStr(to_be_parsed, " ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "IP2: ", 5))
      {
         option = strdup(line+5);
         to_be_parsed = Parser_AddStr(to_be_parsed, " ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "MAC1: ", 6))
      {
         option = strdup(line+6);
         to_be_parsed = Parser_AddStr(to_be_parsed, " ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "MAC2: ", 6))
      {
         option = strdup(line+6);
         to_be_parsed = Parser_AddStr(to_be_parsed, " ");
         to_be_parsed = Parser_AddStr(to_be_parsed, option);
         free(option);
      }

      if (!strncasecmp(line, "GWIP: ", 6))
      {
         extern int illithid_gwip;

         option = strdup(line+6);
         if ( inet_aton(option, (struct in_addr *)&illithid_gwip) == 0)
         {
            Options.normal = 1;  // prevent Error_msg to close the screen
            Error_msg("Incorrect GWIP (%s) in the conf file !!", option);
         }
         free(option);
      }

      if (!strncasecmp(line, "</dissectors>", 13))
         dissectors = 0;

      if (dissectors)
         Parser_Dissectors(line);

      if (!strncasecmp(line, "<dissectors>", 12))
      {
         fprintf (stdout, "Setting dissectors handlers...\n");
         dissectors = 1;
      }
#ifdef PERMIT_PLUGINS
      if (!strncasecmp(line, "</hooking plugins>", 18))
         plugins = 0;

      if (plugins)
         Parser_Plugins(line);

      if (!strncasecmp(line, "<hooking plugins>", 17))
      {
         fprintf (stdout, "Plugins to be loaded...\n");
         plugins = 1;
      }
#endif

   } while (!feof(etterconf));


   if (!strcmp(to_be_parsed, "etter.conf ")) // no options in the file....
      return;

#ifdef DEBUG
      Debug_msg("Parser_ParseConfFile - [%s]", to_be_parsed);
#endif

   ptr = strtok(to_be_parsed, " ");
   pargv[pargc++] = strdup(ptr);

   while( (ptr = strtok(NULL, " ")) )
      pargv[pargc++] = strdup(ptr);

#ifdef DEBUG
{
   int i;
   for(i=0; i<pargc; i++)
      Debug_msg("Parser_ParseConfFile - [%d] %s", i, pargv[i]);

   Debug_msg("Parser_ParseConfFile - pargc [%d]", pargc);
}
#endif

   free(to_be_parsed);

   Parser_ParseOptions(pargc, pargv);
}




void Parser_Dissectors(char *toparse)
{
   char name[15];
   char arguments[25];
   char *parseport;
   char *proto;
   short port=0;

   if (!strchr(toparse, '='))    // malformed line
      return;

   memset(name, 0, sizeof(name));
   memset(arguments, 0, sizeof(arguments));

   strlcpy(name, strtok(toparse, "="), sizeof(name));

   strlcpy(arguments, strtok(NULL, "="), sizeof(arguments));

   if (!strncmp(arguments, "OFF", 3))
   {
      fprintf(stdout, "%11s... disabled!\n", name);
      Dissector_SetHandle(name, 0, 0, 0); // disable this dissector
   }
   else if (!strncmp(arguments, "ON", 2))
   {
      if ( (parseport = strchr(arguments, '|')) )
      {
         parseport++;

         proto = strchr(parseport, '/');
         if (proto)
         {
            proto++;
            port = atoi(strtok(parseport, "/"));

            if (!strncasecmp(proto, "tcp", 3))
               Dissector_SetHandle(name, 1, port, IPPROTO_TCP);
            else if (!strncasecmp(proto, "udp", 3))
               Dissector_SetHandle(name, 1, port, IPPROTO_UDP);
            else if (!strcmp(name, "PROXYHTTPS"))
            {
#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
               extern int Grell_ProxyIP;
               extern int Grell_ProxyPort;
               Grell_ProxyIP = inet_addr(strtok(NULL, "/"));
               Grell_ProxyPort = port;
               Dissector_SetHandle(name, 1, port, IPPROTO_TCP);
#else
               fprintf(stdout, "%11s... not compiled in ettercap !!\n", name);
               return;
#endif
            }
            else
               return;
         }
         else
            return;

         fprintf(stdout, "%11s... moved on port %d/%s\n", name, port, proto);
      }
   }
}



void Parser_Plugins(char *toparse)
{
   char name[20], l_name[22];
   char args[4];

   if (!strchr(toparse, '='))    // malformed line
      return;

   if (!loading_plugs) loading_plugs = (char *)calloc(1,1);

   memset(name, 0, sizeof(name));
   strlcpy(name, strtok(toparse, "="), 20);
   strlcpy(args, strtok(NULL, "="), 4);

   if (!strncmp(args, "ON", 2))
   {
      snprintf(l_name, sizeof(l_name), "|%s|", name);
      loading_plugs = (char *)realloc(loading_plugs, strlen(loading_plugs)+strlen(l_name)+2);
      strcat(loading_plugs, l_name);
      fprintf(stdout, "%s\n", name);
   }
}




char Parser_Activated_Plugin(char *name)
{
   char l_name[22];
   snprintf(l_name, sizeof(l_name), "|%s|", name);

   if (!loading_plugs) return 0;

   if (strstr(loading_plugs, l_name)) return 1;

   return 0;
}



void Parser_Filters(char *line, DROP_FILTER *filter)
{
   int i, j;
   char tmp[50];
   char tmp_search[MAX_FILTER+1];
   char *p, *q;


   if ((p = strstr(line, "<search>")))
   {
      q = strstr(p, "</search>");
      i = ((int)q-(int)p) - strlen("<search>");
      if (i==0) return;
      snprintf(tmp, sizeof(tmp), "<search>%%%dc</search>", i);
      sscanf(p, tmp, filter->display_search);
      filter->wildcard = FilterDrop_ParseWildcard(tmp_search, filter->display_search, sizeof(tmp_search));
      filter->slen = FilterDrop_strescape(filter->search, tmp_search);
      return;
   }

   if ((p = strstr(line, "<replace>")))
   {
      q = strstr(p, "</replace>");
      i = ((int)q-(int)p) - strlen("<replace>");
      if (i==0) return;
      snprintf(tmp,sizeof(tmp) ,"<replace>%%%dc</replace>", i);
      sscanf(p, tmp, filter->display_replace);
      filter->rlen = FilterDrop_strescape(filter->replace, filter->display_replace);
      return;
   }

   if ((p = strstr(line, "<action>")))
   {
      sscanf(p, "<action>%c</action>", &filter->type);
      filter->type = toupper(filter->type);
      return;
   }

   if ((p = strstr(line, "<goto>")))
   {
      j = sscanf(p, "<goto>%d</goto>", &filter->go_to);
      if (j == 0) filter->go_to = -1;
   }

   if ((p = strstr(line, "<elsegoto>")))
   {
      j = sscanf(p, "<elsegoto>%d</elsegoto>", &filter->else_go_to);
      if (j == 0) filter->else_go_to = -1;
   }

   if ((p = strstr(line, "<proto>")))
   {
      sscanf(p, "<proto>%c</proto>", &filter->proto);
      filter->proto = toupper(filter->proto);
      return;
   }

   if ((p = strstr(line, "<source>")))
      sscanf(p, "<source>%d</source>", &filter->source);

   if ((p = strstr(line, "<dest>")))
      sscanf(p, "<dest>%d</dest>", &filter->dest);

}



void Parser_LoadFilters(char *filename)
{
   FILE *etterfilter;
   char line[1024];
   char *ptr;
   char filter=0;
   DROP_FILTER filter_tmp;
   extern char *Filter_File;

   if (Filter_File)
   {
      etterfilter = fopen(Filter_File, "r");
      #ifdef DEBUG
         Debug_msg("Parser_LoadFilters - [%s]", Filter_File);
      #endif
   }
   else if (!strcmp(filename, ""))
   {
      strcpy(line, "./etter.filter");
      etterfilter = fopen(line, "r");
      if (etterfilter == NULL)
      {
         strlcpy(line, DATA_PATH, sizeof(line));
         strlcat(line, "/etter.filter", sizeof(line));
         etterfilter = fopen(line, "r");
      }
      Filter_File = strdup(line);
      #ifdef DEBUG
         Debug_msg("Parser_LoadFilters - [%s]", line);
      #endif
   }
   else
   {
      etterfilter = fopen(filename, "r");
      Filter_File = strdup(filename);
      #ifdef DEBUG
         Debug_msg("Parser_LoadFilters - [%s]", filename);
      #endif
   }

   if (etterfilter == NULL)
         Error_msg("CAN'T find a filter file in ./ or in %s", DATA_PATH);

   Filter_Source = 0;
   Filter_Dest = 0;

   if (Filter_Array_Source) free(Filter_Array_Source);
   if (Filter_Array_Dest) free(Filter_Array_Dest);

   Filter_Array_Source = NULL;
   Filter_Array_Dest = NULL;

   do
   {
      fgets(line, 1024, etterfilter);

      if ( (ptr = strchr(line, '#')) )
         *ptr = 0;

      if (!strlen(line))   // skip 0 length line
         continue;

      if (!strncasecmp(line, "</filter source>", 16))
      {
         filter = 0;
         memcpy(&Filter_Array_Source[Filter_Source-1], &filter_tmp, sizeof(DROP_FILTER));
      }

      if (!strncasecmp(line, "</filter dest>", 14))
      {
         filter = 0;
         memcpy(&Filter_Array_Dest[Filter_Dest-1], &filter_tmp, sizeof(DROP_FILTER));
      }

      if (filter)
         Parser_Filters(line, &filter_tmp);

      if (!strncasecmp(line, "<filter source>", 15))
      {
         Filter_Source++;
         filter = 1;
         memset(&filter_tmp, 0, sizeof(DROP_FILTER));
         Filter_Array_Source = (DROP_FILTER *)realloc(Filter_Array_Source, (Filter_Source) * sizeof(DROP_FILTER));
         if (Filter_Array_Source == NULL)
            ERROR_MSG("realloc()");
      }

      if (!strncasecmp(line, "<filter dest>", 13))
      {
         Filter_Dest++;
         filter = 1;
         memset(&filter_tmp, 0, sizeof(DROP_FILTER));
         Filter_Array_Dest = (DROP_FILTER *)realloc(Filter_Array_Dest, (Filter_Dest) * sizeof(DROP_FILTER));
         if (Filter_Array_Dest == NULL)
            ERROR_MSG("realloc()");
      }

   } while (!feof(etterfilter));

   fclose(etterfilter);

#ifdef DEBUG
{
   short i;
   for (i=0; i<Filter_Source; i++)
      Debug_msg("\tSOURCE: %s", Parser_PrintFilter(Filter_Array_Source, i));

   for (i=0; i<Filter_Dest; i++)
      Debug_msg("\tDEST  : %s", Parser_PrintFilter(Filter_Array_Dest, i));
}
#endif

}


char * Parser_PrintFilter(DROP_FILTER *ptr, int i)
{
   static char tmp[100];
   int j;

   j = snprintf(tmp, sizeof(tmp), "%2d | %5d:%-5d %c [%-10.10s] %c ", i,  ptr[i].source, ptr[i].dest, ptr[i].proto, ptr[i].display_search, ptr[i].type);
   if (ptr[i].type == 'R')
      j += sprintf(tmp+j, "[%-10.10s] ", ptr[i].display_replace);
   else
      j += sprintf(tmp+j, "             ");
   if (ptr[i].go_to >= 0 || ptr[i].else_go_to >= 0)
      j += sprintf(tmp+j, "| => ");
   if (ptr[i].go_to >= 0)
      j += sprintf(tmp+j, "%2d ", ptr[i].go_to);
   else
      j += sprintf(tmp+j, "   ");
   if (ptr[i].else_go_to >= 0)
      j += sprintf(tmp+j, "! %-2d ", ptr[i].else_go_to);

  return tmp;
}



void Parser_Expand(char *to_parse)
{
   static int j=0;
   int i=0, found=0;
   char *q;
   char new_parse[25];
   char ip[25];
   char *pattern;

   memset(new_parse, 0, sizeof(new_parse));
   memset(ip, 0, sizeof(ip));
   pattern = strdup(to_parse);

   if (strstr(pattern, "*") || strstr(pattern, "?"))
   {
      for( q=strtok(pattern, "."); q!=NULL; q=strtok(NULL, "."))
      {
         i++;
         if (!found && (strstr(q, "*") || strstr(q, "?")) )
         {
            strlcat(new_parse, "%d", sizeof(new_parse));
            if (i<4) strlcat(new_parse, ".", sizeof(new_parse));
            found=1;
         }
         else
         {
            strlcat(new_parse, q, sizeof(new_parse));
            if (i<4) strlcat(new_parse, ".", sizeof(new_parse));
         }
      }
   }
   else
   {
      strncpy(new_parse, to_parse, sizeof(new_parse)-1);
      new_parse[sizeof(new_parse)-1]='\0';
   }

   free(pattern);

   if (!found) // no more wildcards
   {
      if (j++%10 == 0)  // the progress bar...
      {
         printf(".");
         fflush(stdout);
      }
      list_to_parse = realloc(list_to_parse, strlen(list_to_parse)+strlen(to_parse)+2);
      if (list_to_parse == NULL)
         ERROR_MSG("realloc()");
      strcat(list_to_parse, to_parse);
      strcat(list_to_parse, ",");
      return;
   }

   for(i=0; i<256; i++)
   {
      snprintf(ip, sizeof(ip), new_parse, i);
      if (match_pattern(ip, to_parse))
         Parser_Expand(ip);
   }
}



int Parser_HostList(char *to_parse)
{
   char *ip;
   u_long dummy;
   int i=0;

#ifdef DEBUG
   Debug_msg("Parser_HostList - [%s]", to_parse);
#endif

   fprintf(stdout, "Expanding wildcarded hosts...");

   if (strstr(to_parse, " "))
   {
      fprintf(stdout, "\n");
      Options.normal = 1;
      Error_msg("The host list can't contain blank spaces...");
   }

   list_to_parse = calloc(1,1);

   for(ip=strsep(&to_parse, ","); ip != NULL; ip=strsep(&to_parse, ","))
      Parser_Expand(ip);

#ifdef DEBUG
   Debug_msg("Parser_HostList - [%s]", list_to_parse);
#endif

   fprintf(stdout, "\nLoading IP addresses from list...\n");

   Host_List = calloc(2, sizeof(char *));
   if (Host_List == NULL)
      ERROR_MSG("calloc()");

   for(ip=strtok(list_to_parse, ","); ip != NULL; ip=strtok(NULL, ","))
   {
      if (inet_aton(ip, (struct in_addr *)&dummy) != 0)
      {
         Host_List[i++] = strdup(ip);
         Host_List = realloc(Host_List, (i+2)*sizeof(char *));
         if (Host_List == NULL)
            ERROR_MSG("realloc()");
      }
      else
         fprintf(stdout, "WARNING: %s is an invalid IP address\n", ip);
   }

   free(list_to_parse);

   return i;
}



/* Pattern matching code from OpenSSH. */
int match_pattern(const char *s, const char *pattern)
{
   for (;;)
   {
      if (!*pattern) return (!*s);

      if (*pattern == '*')
      {
         pattern++;

         if (!*pattern) return (1);

         if (*pattern != '?' && *pattern != '*')
         {
            for (; *s; s++)
            {
               if (*s == *pattern && match_pattern(s + 1, pattern + 1))
                  return (1);
            }
            return (0);
         }
         for (; *s; s++)
         {
            if (match_pattern(s, pattern))
               return (1);
         }
         return (0);
      }
      if (!*s) return (0);

      if (*pattern != '?' && *pattern != *s)
         return (0);

      s++;
      pattern++;
   }
   /* NOTREACHED */
}


char *Parser_StrSpacetoUnder(char *h_name)
{
   int i;
   static char toggle_name[200];

   strcpy(toggle_name, h_name);
   i = strlen(toggle_name);

   for (i--;i>=0;i--)
      if (toggle_name[i]==' ')
         toggle_name[i]='_';

   return toggle_name;
}


/* EOF */

