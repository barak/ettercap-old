
/* $Id: ec_main.h,v 1.22 2002/02/11 20:46:50 alor Exp $ */


#if !defined(EC_MAIN_H)
#define EC_MAIN_H


#ifdef HAVE_CONFIG_H
   #include <config.h>     // autoheader   -I.
#endif

#define DEVEL_RELEASE 0
#define VERSION "0.6.4"
#define PROGRAM "ettercap"
#define AUTHORS "ALoR & NaGA"

#define loop for(;;)

#include <stdio.h>
#include <stdlib.h>
#if defined (LINUX) && !defined (__USE_GNU)  // for memmem(), strsignal(), etc etc...
   #define __USE_GNU
#endif
#include <string.h>
#if defined (__USE_GNU)
   #undef __USE_GNU
#endif
#include <strings.h>
#ifdef CYGWIN
	#include <windows.h>
	#include <winsock2.h>
#else
	#include <sys/types.h>
	#include <sys/time.h>
#endif
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "ec_queue.h"

#ifdef DEBUG
   #include "ec_debug.h"
#endif

#ifndef HAVE_STRLCAT             // missing functions
   #include "../missing/strlcat.h"
#endif
#ifndef HAVE_STRLCPY             // missing functions
   #include "../missing/strlcpy.h"
#endif
#ifndef HAVE_STRSEP              // missing functions
   #include "../missing/strsep.h"
#endif
#ifndef HAVE_MEMMEM              // missing functions
   #include "../missing/memmem.h"
#endif
#ifndef HAVE_SCANDIR             // missing functions
   #include "../missing/scandir.h"
#endif

#if defined (MACOSX) || defined (CYGWIN)
	#define exit_func(x) atexit((void (*)(void))x)
	#define exit_func_end()
#else
	#define exit_func(x)    pthread_cleanup_push(x, (void *)NULL)
	#define exit_func_end() pthread_cleanup_pop(0)
#endif

typedef struct host_arp          // hosts in LAN info
{
   int port;
   char name[128];
   char ip[16];
   char mac[20];
} HOST;


extern HOST *Host_In_LAN;
extern int number_of_hosts_in_lan;

extern HOST Host_Source;
extern HOST Host_Dest;

typedef struct options_list      // arguments passed on command line
{
   char list:1;
   char arpsniff:1;
   char sniff:1;
   char macsniff:1;
   char normal:1;
   char check:1;
   char plugin:1;
   char hexview:1;
   char silent:1;
   char udp:1;
   char finger:1;
   char link:1;
   char collect:1;
   char broadping:1;
   char logtofile:1;
   char quiet:1;
   char dontresolve:1;
   char filter:1;
   char version:1;
   char yes:1;
   char reverse;
   char passive:1;
   char hostsfromfile:1;
   char hoststofile:1;
   char *hostfile;
   char netiface[10];
   char netmask[16];
   short delay;
   u_long spoofIp;
   int storm_delay;
} OPTIONS;

extern OPTIONS Options;

struct open_ports
{
   u_short port;
   char banner[150];
   LIST_ENTRY (open_ports) next;
};


#define FINGER_LEN 28

typedef struct passive_data
{
   char ip[16];
   char mac[20];
   char fingerprint[FINGER_LEN+1];
   char os[60];
   char type[5];
   char gwforthis[16];
   char name[18];
   u_short port;
   char proto;
   short hop;
   char banner[150];
   LIST_HEAD (,open_ports) tcp_ports;
   LIST_HEAD (,open_ports) udp_ports;
} PASSIVE_DATA;

extern PASSIVE_DATA *Passive_Host;
extern int number_of_passive_hosts;


#define MAX_DATA 2000

typedef struct sniffed_data   // data through the pipe with illithid
{
   char source_ip[16];
   char dest_ip[16];
   u_long fast_source_ip;
   u_long fast_dest_ip;
   u_short source_port;
   u_short dest_port;
   u_long seq;
   u_long ack_seq;
   char flags;
   char proto;
   short datasize;
   char data[MAX_DATA];     // FIXME: to be resized...
} SNIFFED_DATA;


typedef struct current_sniffed_data
{
   u_long source_ip;
   u_long dest_ip;
   u_short source_port;
   u_short dest_port;
   char proto;
} CURRENT_SNIFFED_DATA;

extern CURRENT_SNIFFED_DATA current_illithid_data;

typedef struct {
   int Host_Index1;
   int Host_Index2;
   u_char mode;
} SniffingHost;


typedef struct connection        // connection list
{
   char source_ip[16];
   char dest_ip[16];
   char source_mac[20];
   char dest_mac[20];
   u_long fast_source_ip;
   u_long fast_dest_ip;
   u_short source_port;
   u_short dest_port;
   u_long source_seq;
   u_long dest_seq;
   char flags;
   char proto;
   short datalen;
   char status[8];
   time_t timestamp;
   char type[18];          // from /etc/services
   char user[30];          // pay attention on buffer overflow !!
   char pass[30];
   char info[150];         // additional info... ( smb domain, http page ...)
} CONNECTION;


typedef struct dissect		// structs to be passed to Plugin_HookPoint
{
   u_char *layer4;
   CONNECTION *connection;
} DISSECTION;

typedef struct raw_pck
{
   u_char *buffer;
   int *len;
} RAW_PACKET;


#define MAX_INJECT 1000          // max number of injected chars
#define MAX_FILTER 200           // max filter length

typedef struct {                 // filter structure (ec_filterdrop.c)
   u_char display_search[MAX_FILTER+1];
   u_char display_replace[MAX_FILTER+1];
   char proto;
   int source;
   int dest;
   u_char search[MAX_FILTER+1];
   short slen;
   short wildcard;
   char type;
   u_char replace[MAX_FILTER+1];
   short rlen;
   int go_to;
   int else_go_to;
   char validate;
} DROP_FILTER;

extern DROP_FILTER *Filter_Array_Source;  // ec_filterdrop.c
extern DROP_FILTER *Filter_Array_Dest;
extern int Filter_Source;
extern int Filter_Dest;

typedef struct {                 // injecting structure
   u_long source_ip;
   u_long dest_ip;
   u_short source_port;
   u_short dest_port;
   char proto;
   char data[MAX_INJECT+1];
   short datalen;
} INJECTED_DATA;

typedef struct {                 // killing structure
   u_long source_ip;
   u_long dest_ip;
   u_short source_port;
   u_short dest_port;
} KILL_DATA;

extern CONNECTION *Conn_Between_Hosts;
extern int number_of_connections;

extern int pipe_with_illithid_data;
extern int pipe_with_plugins;
extern int pipe_inject[2];
extern int pipe_kill[2];

extern char active_dissector;    // ec_main.c
extern char filter_on_source;
extern char filter_on_dest;
extern int Connection_Mode;      // ec_illithid.c

#if defined(HAVE_GETTIMEOFDAY) && !defined(CYGWIN)
   #define TIME_DECLARE struct timeval start, finish
   #define TIME_START   gettimeofday(&start, 0)
   #define TIME_FINISH  gettimeofday(&finish, 0)
   #define TIME_ELAPSED (finish.tv_sec + finish.tv_usec/1.0e6)-(start.tv_sec  + start.tv_usec/1.0e6)
#else
   #define TIME_DECLARE float start, finish
   #define TIME_START   start=clock()
   #define TIME_FINISH  finish=clock()
   #define TIME_ELAPSED ((finish-start)/CLOCKS_PER_SEC)
#endif


#define ARPBASED  0  // illithid modus operandi
#define PUBLICARP 1
#define IPBASED   2
#define MACBASED  3


#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
   #define HTTPS_Local_Port (unsigned short)1012         // local port for HTTPS dissection
   #define Proxy_Local_Port (unsigned short)1013
   #define CERT_FILE "etter.ssl.crt"
#endif


extern char **Host_List;
extern int host_to_be_scanned;

#define DEFAULT_DELAY 30            // in seconds, delay between arp replies
#define DEFAULT_STORM_DELAY 1500    // in microseconds, delay between inizial arp request

#include "ec_install_path.h"

#define OS_FILE "etter.passive.os.fp"

#define CONN_TIME_SILENT   1        // in seconds, the time to change the connection status from ACTIVE to silent
#define CONN_TIME_TIMEOUT  1200


#endif	// EC_MAIN_H

/* EOF */
