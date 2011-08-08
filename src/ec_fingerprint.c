/*
    ettercap -- fingerprinter

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

    $Id: ec_fingerprint.c,v 1.8 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#include <fcntl.h>

#include "include/ec_inet_structures.h"
#include "include/ec_inet.h"
#include "include/ec_inet_forge.h"
#include "include/ec_decodedata.h"
#include "include/ec_error.h"

#ifdef HAVE_SYS_UTSNAME_H
   #include <sys/utsname.h>
#endif

#define NUM_TESTS 7
#define NUM_CONDS 6

#define MSS 265

// global data...

typedef struct
{
   char mac[9];
   char vendor[60];
   struct mac_database *next;
} mac_database;

mac_database *mac_list = NULL;

int IPS, IPD, sock, MTU;
u_short open_port=0, closed_port=0, PORTS;
long SYN_SEQ;
unsigned short IP_ID;
unsigned char MACS[6];
unsigned char MACD[6];
// Static arrays? bleah...
char packet_stamp[NUM_TESTS][NUM_CONDS][10];
char test_name[NUM_CONDS][10];

// protos....

char * Fingerprint_OS(char *IP);
char * Fingerprint_MAC(char *MAC);
char *Fingerprint_Make_Finger_print(void);
int Fingerprint_Match(char *mycond, char *fpcond);
void Fingerprint_send_probes(void);
void Fingerprint_parse_probes(void);
void Fingerprint_Init_Test(void);
void Fingerprint_Simple_Scan(void);
void Fingerprint_Parse_packet(char *buffer);

//--------------------------


int Fingerprint_Match(char *mycond, char *fpcond)
{
   int matched=0; char *single_cond, *deadend=NULL, temp=0;

   deadend=fpcond+strlen(fpcond);
   if (deadend==fpcond) matched=1;
   while( !matched && (unsigned long)fpcond<(unsigned long)deadend )
   {
      single_cond=(char *)strtok(fpcond,"|");
      if (!single_cond) // Simple workaround for initial '|'
      {                 // Arghhh someone wrote down terrible fingerprints
         if (temp) break;
         fpcond++;
         temp=1;
         continue;
      }
     if (!strcmp(mycond,single_cond)) matched=1;
     fpcond+=strlen(single_cond)+1;
     temp=0;
   }
   return matched;
}

void Fingerprint_send_probes()
{
   char *probe_pck;

#define TH_BOGUS 64
#define OPTIONS "\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000"
#define OPT_LEN 20

   PORTS++;
   probe_pck=(char *)Inet_Forge_packet(ETH_HEADER + IP_HEADER + TCP_HEADER + OPT_LEN);
   Inet_Forge_ethernet( probe_pck, MACS, MACD, ETH_P_IP );

   Inet_Forge_ip( probe_pck + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
   Inet_Forge_tcp( probe_pck + ETH_HEADER + IP_HEADER, PORTS, open_port,  SYN_SEQ, 0, TH_BOGUS|TH_SYN, 0, 0);
   Inet_Forge_Insert_TCPOpt( probe_pck + ETH_HEADER + IP_HEADER, OPTIONS , OPT_LEN);
   Inet_SendRawPacket(sock, probe_pck, ETH_HEADER + IP_HEADER + TCP_HEADER + OPT_LEN);

   Inet_Forge_ip( probe_pck + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
   Inet_Forge_tcp( probe_pck + ETH_HEADER + IP_HEADER, PORTS+1, open_port,  SYN_SEQ, 0, 0, 0, 0);
   Inet_Forge_Insert_TCPOpt( probe_pck + ETH_HEADER + IP_HEADER, OPTIONS ,OPT_LEN );
   Inet_SendRawPacket(sock, probe_pck, ETH_HEADER + IP_HEADER + TCP_HEADER + OPT_LEN);

   Inet_Forge_ip( probe_pck + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
   Inet_Forge_tcp( probe_pck + ETH_HEADER + IP_HEADER, PORTS+2, open_port,  SYN_SEQ, 0, TH_SYN|TH_FIN|TH_URG|TH_PSH, 0, 0);
   Inet_Forge_Insert_TCPOpt( probe_pck + ETH_HEADER + IP_HEADER, OPTIONS ,OPT_LEN );
   Inet_SendRawPacket(sock, probe_pck, ETH_HEADER + IP_HEADER + TCP_HEADER + OPT_LEN);

   Inet_Forge_ip( probe_pck + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
   Inet_Forge_tcp( probe_pck + ETH_HEADER + IP_HEADER, PORTS+3, open_port,  SYN_SEQ, 0, TH_ACK, 0, 0);
   Inet_Forge_Insert_TCPOpt( probe_pck + ETH_HEADER + IP_HEADER, OPTIONS ,OPT_LEN );
   Inet_SendRawPacket(sock, probe_pck, ETH_HEADER + IP_HEADER + TCP_HEADER + OPT_LEN );

   Inet_Forge_ip( probe_pck + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
   Inet_Forge_tcp( probe_pck + ETH_HEADER + IP_HEADER, PORTS+4, closed_port,  SYN_SEQ, 0, TH_SYN, 0, 0);
   Inet_Forge_Insert_TCPOpt( probe_pck + ETH_HEADER + IP_HEADER, OPTIONS ,OPT_LEN );
   Inet_SendRawPacket(sock, probe_pck, ETH_HEADER + IP_HEADER + TCP_HEADER + OPT_LEN );

   Inet_Forge_ip( probe_pck + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
   Inet_Forge_tcp( probe_pck + ETH_HEADER + IP_HEADER, PORTS+5, closed_port,  SYN_SEQ, 0, TH_ACK, 0, 0);
   Inet_Forge_Insert_TCPOpt( probe_pck + ETH_HEADER + IP_HEADER, OPTIONS ,OPT_LEN );
   Inet_SendRawPacket(sock, probe_pck, ETH_HEADER + IP_HEADER + TCP_HEADER + OPT_LEN );

   Inet_Forge_ip( probe_pck + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);
   Inet_Forge_tcp( probe_pck + ETH_HEADER + IP_HEADER, PORTS+6, closed_port,  SYN_SEQ, 0, TH_FIN|TH_PSH|TH_URG, 0, 0);
   Inet_Forge_Insert_TCPOpt( probe_pck + ETH_HEADER + IP_HEADER, OPTIONS ,OPT_LEN );
   Inet_SendRawPacket(sock, probe_pck, ETH_HEADER + IP_HEADER + TCP_HEADER + OPT_LEN );

   Inet_Forge_packet_destroy( probe_pck );
}

void Fingerprint_parse_probes()
{
   ETH_header *eth;
   IP_header *ip;
   TCP_header *tcp;
   short type;
   int len;
   char *probe_pck;

   TIME_DECLARE;
   TIME_START;
   probe_pck=(char *)Inet_Forge_packet(MTU);

   do
   {
   len=Inet_GetRawPacket(sock,probe_pck,MTU,&type);
   TIME_FINISH;

   if (len>0 && type==PACKET_HOST)
   {
      eth=(ETH_header *)probe_pck;
      if (ntohs(eth->type)==ETH_P_IP)
      {
      ip=(IP_header *)(probe_pck+ETH_HEADER);
      if (ip->proto==IPPROTO_TCP && ip->source_ip==IPD)
      {
         tcp=(TCP_header *)(probe_pck+ETH_HEADER+IP_HEADER);

         if ( (u_short)ntohs(tcp->dest)>=PORTS && (u_short)ntohs(tcp->dest)<PORTS+NUM_TESTS)
         {
         char *p, *q, *arrive;
         unsigned int num_test;

         num_test=ntohs(tcp->dest)-PORTS;

         // Replied
         strcpy(&packet_stamp[num_test][0][0],"Y");
            // DF flag
         if(ntohs(ip->frag_and_flags) & 0x4000)
         {
            strcpy(&packet_stamp[num_test][1][0],"Y");
         }
         else strcpy(&packet_stamp[num_test][1][0], "N");
         // Window Size
         sprintf(&packet_stamp[num_test][2][0],"%hX",ntohs(tcp->window));
         // ACK Sequence
         if (ntohl(tcp->ack_seq) == SYN_SEQ+1)
            strcpy(&packet_stamp[num_test][3][0],"S++");
         else if (ntohl(tcp->ack_seq) == SYN_SEQ)
            strcpy(&packet_stamp[num_test][3][0],"S");
         else
            strcpy(&packet_stamp[num_test][3][0],"O");
         // Flags
         p=&packet_stamp[num_test][4][0];
         *p='\0';
         if (tcp->flags & 0x40)   *p++='B'; // BOGUS
         if (tcp->flags & TH_URG) *p++='U';
         if (tcp->flags & TH_ACK) *p++='A';
         if (tcp->flags & TH_PSH) *p++='P';
         if (tcp->flags & TH_RST) *p++='R';
         if (tcp->flags & TH_SYN) *p++='S';
         if (tcp->flags & TH_FIN) *p++='F';
         *p++='\0';
         // TCP Options
         p=&packet_stamp[num_test][5][0];
         q=((char *)tcp) + TCP_HEADER;
         arrive = ((char *)tcp) + (tcp->doff*4);
         while(q<arrive)
         {
            int opcode;

            opcode=*q++;
            if (!opcode) {
            *p++ = 'L';
            break;
            } else if (opcode == 1) {
              *p++ = 'N';
            } else if (opcode == 2) {
              *p++ = 'M';
              q++;
              if (ntohs(ptohs(q)) == MSS)
               *p++ = 'E';
              q+=2;
            } else if (opcode == 3) {
              *p++ = 'W';
              q+=2;
            } else if (opcode == 8) {
              *p++ = 'T';
              q+=9;
            }
         }
         *p++='\0';
         }
      }
      }
   }
   }while(TIME_ELAPSED<1);

   Inet_Forge_packet_destroy( probe_pck );
}


void Fingerprint_Init_Test()
{
   sprintf(test_name[0],"Resp");
   sprintf(test_name[1],"DF");
   sprintf(test_name[2],"W");
   sprintf(test_name[3],"ACK");
   sprintf(test_name[4],"Flags");
   sprintf(test_name[5],"Ops");

   strcpy(&packet_stamp[0][0][0],"N");
   strcpy(&packet_stamp[1][0][0],"N");
   strcpy(&packet_stamp[2][0][0],"N");
   strcpy(&packet_stamp[3][0][0],"N");
   strcpy(&packet_stamp[4][0][0],"N");
   strcpy(&packet_stamp[5][0][0],"N");
   strcpy(&packet_stamp[6][0][0],"N");
}

char *Fingerprint_Make_Finger_print()
{
   FILE *file;
   int i, no_match=1;
   char dummy[500];
   char num_test[5];
   char *condition;
   char *test;
   static char osname[500];
   static char res_list[2000];

   file = fopen(DATA_PATH "/nmap-os-fingerprints", "r");
   if (!file)
      file = fopen("./share/nmap-os-fingerprints","r");
      if (!file)
         Error_msg("Can't open \"nmap-os-fingerprints\" file !!");


   Fingerprint_Init_Test();
   Fingerprint_send_probes();
   Fingerprint_parse_probes();
   res_list[0]=0;

   loop
   {
      char *To_EOF;

      while( (To_EOF=fgets(osname,500,file)) && !strstr(osname,"Fingerprint") );
      if (!To_EOF) break;
      no_match=0;
      for (i=1; i<=7 && !no_match; i++)
      {
         char *deadend;

         snprintf(num_test, sizeof(num_test), "T%1d", i);
         while(fgets(dummy,500,file) && !strstr(dummy,num_test));

         test=dummy+3;
         dummy[strlen(dummy)-2]=0;
         deadend=test+strlen(test);

         while( !no_match &&  (unsigned long)test<(unsigned long)deadend )
         {
            int j; char *pos=NULL;
            condition=(char *)strtok(test,"%");
            test+=strlen(condition)+1;
            for (j=0; j<NUM_CONDS && pos!=condition; j++)
               pos=(char *)strstr(condition,test_name[j]);
            condition +=  strlen(test_name[j-1])+1;
            if ( !Fingerprint_Match(&packet_stamp[i-1][j-1][0],condition) ) no_match=1;
         }
      }
      if (!no_match)
      {
         strlcat(res_list, osname+sizeof("Fingerprint"), sizeof(res_list));
      }
   }
   fclose(file);

   if (!strcmp(res_list, ""))
      strcpy(res_list, "Not found in the database\n");

   return res_list;

}


void Fingerprint_Parse_packet(char *buffer)
{
   IP_header  *ip;
   TCP_header *tcp;

   ip = (IP_header *) (buffer+ETH_HEADER);
   if (ip->source_ip==IPD && ip->dest_ip==IPS && ip->proto==IPPROTO_TCP)
   {
     tcp = (TCP_header *) ((int)ip + ip->h_len * 4);
     if ( (tcp->flags & TH_SYN) && (tcp->flags & TH_ACK) )
        open_port=ntohs(tcp->source);
     if ( (tcp->flags & TH_RST) && ntohs(tcp->dest)==PORTS )
        closed_port=ntohs(tcp->source);
   }
}

void Fingerprint_Simple_Scan()
{
   int i, startP, finP;
   char *pck_to_send;
   TIME_DECLARE;

   startP = 10;  finP = 150;

   pck_to_send = (char *)Inet_Forge_packet(MTU);
   Inet_Forge_ethernet( pck_to_send, MACS, MACD, ETH_P_IP );
   Inet_Forge_ip( pck_to_send + ETH_HEADER, IPS, IPD, TCP_HEADER, IP_ID++, 0, IPPROTO_TCP);

   for (i=startP; i<=finP; i++)
   {
      Inet_Forge_tcp( pck_to_send + ETH_HEADER + IP_HEADER, PORTS, i,  SYN_SEQ, 0, TH_SYN, 0, 0);
      Inet_SendRawPacket(sock, pck_to_send, ETH_HEADER + IP_HEADER + TCP_HEADER );
      if (!(i%5)) usleep(500);
   }

   TIME_START;
   do
   {
      Inet_GetRawPacket(sock, pck_to_send, MTU, NULL);
      Fingerprint_Parse_packet(pck_to_send);
      TIME_FINISH;
   } while (TIME_ELAPSED <2 && (!open_port || !closed_port) );
   Inet_Forge_packet_destroy( pck_to_send );
}



char * Fingerprint_OS(char *IP)
{
   char *res_name;

#ifdef DEBUG
   Debug_msg("Fingerprint_OS -- [%s]", IP);
#endif

   if (!strcmp(IP, Inet_MyIPAddress()))
   {
      #ifdef HAVE_SYS_UTSNAME_H
         struct utsname buf;

         res_name = (char *)malloc(50);
         uname(&buf);
         strlcpy(res_name, buf.sysname, 50);
         strlcat(res_name, " ", 50);
         strlcat(res_name, buf.release, 50);
         return res_name;
      #else
         return "Yourself ;) try `uname -sr`";
      #endif
   }

   IPD = inet_addr(IP);
   sock = Inet_OpenRawSock(Options.netiface);
   fcntl(sock, F_SETFL, O_NONBLOCK);
   Inet_GetIfaceInfo(Options.netiface, &MTU, MACS, (unsigned long *)&IPS, 0);
   memcpy(MACD, Inet_MacFromIP(inet_addr(IP)), 6);
   srand(time(0)); IP_ID = PORTS = SYN_SEQ = rand()%(0xFFFE)+1;

   open_port = 0;
   closed_port = 0;

   Fingerprint_Simple_Scan();
   if (!open_port || !closed_port)
   {
      Inet_CloseRawSock(sock);
      return "Can't find ports to probe";
   }
   else
   {
      res_name = Fingerprint_Make_Finger_print();
      Inet_CloseRawSock(sock);
      if (!res_name)
         return "No match in database";
      else
         return res_name;
   }

}



char * Fingerprint_MAC(char *MAC)
{
   FILE *fto;
   char line[1024];
   mac_database *mac_index;

#ifdef DEBUG
   Debug_msg("Fingerprint_MAC -- [%s]", MAC);
#endif

   if (!strcmp(MAC, "")) return "unknown";

   if (mac_list == NULL)  // only the first time
   {

      if ( (mac_index = (mac_database *)calloc(1,sizeof(mac_database))) == NULL)
         ERROR_MSG("calloc()");

      mac_list = mac_index;

      fto = fopen(DATA_PATH "/mac-fingerprints", "r");
      if (!fto)
         fto = fopen("./share/mac-fingerprints","r");
         if (!fto)
            Error_msg("Can't open \"mac-fingerprints\" file !!");


      while (fgets (line, 1024, fto))
      {
         if (!strlen(line))   // skip 0 length line
            continue;

         line[strlen(line)-1] = 0;

         if ( (mac_index->next = ( struct mac_database *) calloc (1, sizeof(mac_database))) == NULL)
            ERROR_MSG("calloc()");

         strlcpy(mac_index->mac, line, sizeof(mac_index->mac));
         strlcpy(mac_index->vendor, line+10, 60);

         mac_index = (mac_database *) mac_index->next;
      }

      fclose (fto);
      mac_index->next = NULL;
   }

   mac_index = mac_list;
   for( ; mac_index; mac_index = (mac_database *)mac_index->next)
   {
      if (!strncmp(mac_index->mac, MAC, 8))
      {
         return mac_index->vendor;
      }
   }
   return "unknown";
}


/* EOF */
