/*
    ettercap -- ncurses interface packet factory

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

    $Id: ec_interface_factory.c,v 1.6 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_NCURSES  // don't compile if ncurses interface is not supported

#ifdef HAVE_NCURSES_H
   #include <ncurses.h>
#else
   #include <curses.h>
#endif
#ifdef HAVE_CTYPE_H
   #include <ctype.h>
#endif
#ifdef HAVE_FORM
   #include <form.h>
#endif

#include "include/ec_interface.h"
#include "include/ec_error.h"
#include "include/ec_inet_forge.h"
#include "include/ec_inet.h"
#include "include/ec_inet_structures.h"
#include "include/ec_filterdrop.h"
#ifdef HAVE_FORM
   #include "include/ec_interface_form.h"
#endif

#define BOTTOM_COLOR 1        // color schemes
#define TITLE_COLOR  2
#define MAIN_COLOR   3
#define POINT_COLOR  4
#define SEL_COLOR    5
#define HELP_COLOR   6
#define SNIFF_COLOR  7


// protos...

int Interface_Factory_Run(void);
int Interface_Factory_ETH(u_char *buf);
int Interface_Factory_IP(u_char *buf, short *proto);
int Interface_Factory_TCP(u_char *buf);
int Interface_Factory_UDP(u_char *buf);
int Interface_Factory_RAW(u_char *buf);

// global variables

extern WINDOW *main_window;

extern int Conn_Pointer;

extern int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2;
extern int W_BOTTOMY2;


//---------------------------


#ifdef HAVE_FORM

int Interface_Factory_ETH(u_char *buf)
{
   WINDOW *w;
   FORM *form;
   FIELD *eth_form[8];
   int finished = 0, c;
   unsigned n = 0;
   short len = -1;

#ifdef DEBUG
   Debug_msg("Interface_Factory_ETH");
#endif

   refresh();

   eth_form[n++] = make_label(0, 15, "Ethernet Header");
   eth_form[n++] = make_label(0, 47, " ");
   eth_form[n++] = make_label(2, 0, "Source MAC :");
   eth_form[n++] = make_field(2, 13, 1, 17, FALSE);
   eth_form[n++] = make_label(3, 0, "Dest   MAC :");
   eth_form[n++] = make_field(3, 13, 1, 17, FALSE);
   eth_form[n++] = make_label(4, 0, "Type : IP (0x0800)");
   eth_form[n++] = (FIELD *)0;


   form = new_form(eth_form);
   display_form(form);
   w = form_win(form);

   if (!Conn_Between_Hosts)
   {
      set_field_buffer(eth_form[3], 0, Host_Source.mac);
      set_field_buffer(eth_form[5], 0, Host_Dest.mac);
   }
   else
   {
      set_field_buffer(eth_form[3], 0, Conn_Between_Hosts[Conn_Pointer].source_mac);
      set_field_buffer(eth_form[5], 0, Conn_Between_Hosts[Conn_Pointer].dest_mac);
   }

   curs_set(1);
   //form_driver(form, REQ_OVL_MODE);

   finished = get_form_data(form, w);

   erase_form(form);
   free_form(form);

   if (finished == 2)
   {
      ETH_header *eth;

      eth = (ETH_header *) buf;

      if (Inet_GetMACfromString(field_buffer(eth_form[3], 0), eth->source_mac) == -1)
      {
         Interface_PopUp("Bad MAC parsing !! sould be in the form [01:02:03:04:05:06] !!");
         curs_set(0);
         return -1;
      }

      if (Inet_GetMACfromString(field_buffer(eth_form[5], 0), eth->dest_mac) == -1)
      {
         Interface_PopUp("Bad MAC parsing !! sould be in the form [01:02:03:04:05:06] !!");
         curs_set(0);
         return -1;
      }

      #ifdef DEBUG
         Debug_msg("Interface_Factory_ETH -- [%s]",field_buffer(eth_form[3], 0));
         Debug_msg("Interface_Factory_ETH -- [%s]",field_buffer(eth_form[5], 0));
      #endif

      eth->type = htons(ETH_P_IP);
      len = ETH_HEADER;
   }

   for (c = 0; eth_form[c] != 0; c++)
      free_field(eth_form[c]);

   curs_set(0);

   return len;
}


int Interface_Factory_IP(u_char *buf, short *proto)
{
   WINDOW *w;
   FORM *form;
   FIELD *ip_form[17];
   int finished = 0, c;
   unsigned n = 0;
   short len = -1;

#ifdef DEBUG
   Debug_msg("Interface_Factory_IP");
#endif

   refresh();

   ip_form[n++] = make_label(0, 18, "IP Header");
   ip_form[n++] = make_label(0, 47, " ");
   ip_form[n++] = make_label(2, 0, "Source IP :");
   ip_form[n++] = make_field(2, 12, 1, 17, FALSE);
   ip_form[n++] = make_label(3, 0, "Dest   IP :");
   ip_form[n++] = make_field(3, 12, 1, 17, FALSE);
   ip_form[n++] = make_label(5, 0, "Ident    : 0x");
   ip_form[n++] = make_field(5, 13, 1, 4, FALSE);
   ip_form[n++] = make_label(6, 0, "TTL      : 0x");
   ip_form[n++] = make_field(6, 13, 1, 2, FALSE);
   ip_form[n++] = make_label(7, 0, "Protocol : 0x");
   ip_form[n++] = make_field(7, 13, 1, 2, FALSE);
   ip_form[n++] = make_label(7, 20, "(tcp = 06  udp = 11)");
   ip_form[n++] = make_label(8, 0, "CheckSum : 0x");
   ip_form[n++] = make_field(8, 13, 1, 4, FALSE);
   ip_form[n++] = make_label(8, 20, "(leave blank for auto)");
   ip_form[n++] = (FIELD *)0;


   form = new_form(ip_form);
   display_form(form);
   w = form_win(form);

   set_field_buffer(ip_form[9], 0, "80");

   if (!Conn_Between_Hosts)
   {
      set_field_buffer(ip_form[3], 0, Host_Source.ip);
      set_field_buffer(ip_form[5], 0, Host_Dest.ip);
      set_field_buffer(ip_form[11], 0, "06");
   }
   else
   {
      set_field_buffer(ip_form[3], 0, Conn_Between_Hosts[Conn_Pointer].source_ip);
      set_field_buffer(ip_form[5], 0, Conn_Between_Hosts[Conn_Pointer].dest_ip);
      if (Conn_Between_Hosts[Conn_Pointer].proto == 'T')
         set_field_buffer(ip_form[11], 0, "06");
      else
         set_field_buffer(ip_form[11], 0, "11");
   }

   curs_set(1);
   //form_driver(form, REQ_OVL_MODE);

   finished = get_form_data(form, w);

   erase_form(form);
   free_form(form);

   if (finished == 2)
   {
      IP_header *ip;

      ip = (IP_header *) buf;

      ip->h_len          = 5;
      ip->version        = 4;
      ip->tos            = 0;
      ip->t_len          = htons(IP_HEADER);    // to be calculated after payload len
      ip->ident          = htons(strtoul(field_buffer(ip_form[7], 0), NULL, 16));
      ip->frag_and_flags = htons(0x4000);       // don't fragment
      ip->ttl            = strtoul(field_buffer(ip_form[9], 0), NULL, 16);
      ip->proto          = strtoul(field_buffer(ip_form[11], 0), NULL, 16);
      ip->checksum       = 0;                   // to be calculated after header completion
      ip->source_ip      = inet_addr(field_buffer(ip_form[3], 0));
      ip->dest_ip        = inet_addr(field_buffer(ip_form[5], 0));

      #ifdef DEBUG
         Debug_msg("Interface_Factory_IP -- [%s]", int_ntoa(ip->source_ip));
         Debug_msg("Interface_Factory_IP -- [%s]", int_ntoa(ip->dest_ip));
      #endif

      if (strtoul(field_buffer(ip_form[14], 0), NULL, 16))
         ip->checksum    = htons(strtoul(field_buffer(ip_form[14], 0), NULL, 16));

      *proto = ip->proto;
      len = IP_HEADER;
   }

   for (c = 0; ip_form[c] != 0; c++)
      free_field(ip_form[c]);

   curs_set(0);

   return len;
}


int Interface_Factory_TCP(u_char *buf)
{
   WINDOW *w;
   FORM *form;
   FIELD *tcp_form[21];
   int finished = 0, c;
   unsigned n = 0;
   short len = -1;

#ifdef DEBUG
   Debug_msg("Interface_Factory_TCP");
#endif

   refresh();

   tcp_form[n++] = make_label(0, 18, "TCP Header");
   tcp_form[n++] = make_label(0, 50, " ");
   tcp_form[n++] = make_label(2, 0, "Source port :");
   tcp_form[n++] = make_field(2, 14, 1, 5, FALSE);
   tcp_form[n++] = make_label(2, 22, "Dest port   :");
   tcp_form[n++] = make_field(2, 36, 1, 5, FALSE);
   tcp_form[n++] = make_label(3, 0, "Sequence : 0x");
   tcp_form[n++] = make_field(3, 13, 1, 8, FALSE);
   tcp_form[n++] = make_label(3, 22, "Acknowledge : 0x");
   tcp_form[n++] = make_field(3, 38, 1, 8, FALSE);
   tcp_form[n++] = make_label(4, 0, "Flags    : ");
   tcp_form[n++] = make_field(4, 11, 1, 5, FALSE);
   tcp_form[n++] = make_label(4, 20, "(S/A/P/R/F)");
   tcp_form[n++] = make_label(5, 0, "CheckSum : 0x");
   tcp_form[n++] = make_field(5, 13, 1, 4, FALSE);
   tcp_form[n++] = make_label(5, 20, "(leave blank for auto)");
   tcp_form[n++] = make_label(7, 0, "Payload :");
   tcp_form[n++] = make_field(8, 0, 8, 50, FALSE);
   tcp_form[n++] = make_label(17, 0, "Or load Payload from file:");
   tcp_form[n++] = make_field(18, 0, 1, 50, FALSE);
   tcp_form[n++] = (FIELD *)0;


   form = new_form(tcp_form);
   display_form(form);
   w = form_win(form);

   set_field_buffer(tcp_form[11], 0, "PA");

   if (!Conn_Between_Hosts)
   {
      char port[5];
      snprintf(port, sizeof(port), "%d", Host_Source.port);
      set_field_buffer(tcp_form[3], 0, port);
      snprintf(port, sizeof(port), "%d", Host_Dest.port);
      set_field_buffer(tcp_form[5], 0, port);
   }
   else
   {
      char tmp[10];
      snprintf(tmp, sizeof(tmp), "%d", Conn_Between_Hosts[Conn_Pointer].source_port);
      set_field_buffer(tcp_form[3], 0, tmp);
      snprintf(tmp, sizeof(tmp), "%d", Conn_Between_Hosts[Conn_Pointer].dest_port);
      set_field_buffer(tcp_form[5], 0, tmp);
      snprintf(tmp, sizeof(tmp), "%lx", Conn_Between_Hosts[Conn_Pointer].source_seq);
      set_field_buffer(tcp_form[7], 0, tmp);
      snprintf(tmp, sizeof(tmp), "%lx", Conn_Between_Hosts[Conn_Pointer].dest_seq);
      set_field_buffer(tcp_form[9], 0, tmp);
   }

   curs_set(1);
   //form_driver(form, REQ_OVL_MODE);

   finished = get_form_data(form, w);

   erase_form(form);
   free_form(form);

   if (finished == 2)
   {
      TCP_header *tcp;
      IP_header *ip;
      u_char tmp[8*50 + 5];
      u_char payload[8*50];
      int datalen, i;
      char flags = 0;

      ip = (IP_header *) (buf - IP_HEADER);     // we assume no IP Options !!
      tcp = (TCP_header *) buf;

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, field_buffer(tcp_form[19], 0), 50);
      trim_buffer(tmp, ' ');
      if (strlen(tmp) != 0)   // load from file
      {
         FILE *fts;
         fts = fopen(tmp, "r");
         if (!fts)
         {
            Interface_PopUp("File not found !!");
            return len;
         }
         fseek(fts, 0, SEEK_END);
         #ifdef DEBUG
            Debug_msg("Interface_Factory_TCP -- file opened [%s] size %d", tmp, ftell(fts));
         #endif
         if (ftell(fts) + 40 > 1500)
         {
            Interface_PopUp("File too big (max 1460 bytes)");
            return len;
         }
         rewind(fts);
         fgets(tmp, 1460, fts);
         datalen = FilterDrop_strescape(payload, tmp);
      }
      else
      {
         memset(tmp, 0, sizeof(tmp));
         memcpy(tmp, field_buffer(tcp_form[17], 0), 8*50);
         trim_buffer(tmp, ' ');
         datalen = FilterDrop_strescape(payload, tmp);
      }

      memset(tmp, 0, 10);
      memcpy(tmp, field_buffer(tcp_form[11], 0), 5);
      for(i=0; i<=strlen(tmp); i++)
         switch(tmp[i])
         {
            case 'A':
            case 'a':
                     flags |= TH_ACK;
                     break;
            case 'P':
            case 'p':
                     flags |= TH_PSH;
                     break;
            case 'F':
            case 'f':
                     flags |= TH_FIN;
                     break;
            case 'S':
            case 's':
                     flags |= TH_SYN;
                     break;
            case 'R':
            case 'r':
                     flags |= TH_RST;
                     break;
         }


      tcp->source      = htons(strtoul(field_buffer(tcp_form[3], 0), NULL, 10));
      tcp->dest        = htons(strtoul(field_buffer(tcp_form[5], 0), NULL, 10));
      tcp->seq         = htonl(strtoul(field_buffer(tcp_form[7], 0), NULL, 16));
      tcp->ack_seq     = htonl(strtoul(field_buffer(tcp_form[9], 0), NULL, 16));
      tcp->flags       = flags;
      tcp->unused      = 0;
      tcp->doff        = 5;
      tcp->window      = htons(32120);
      tcp->checksum    = 0;
      tcp->urg_ptr     = 0;

      #ifdef DEBUG
         Debug_msg("Interface_Factory_TCP -- [%d]", ntohs(tcp->source));
         Debug_msg("Interface_Factory_TCP -- [%d]", ntohs(tcp->dest));
      #endif

      ip->t_len        += htons(TCP_HEADER + datalen);
      if (!ip->checksum) ip->checksum = Inet_Forge_ChecksumIP( (u_short *)ip, sizeof(IP_header) );

      if (datalen)
         memcpy(buf + TCP_HEADER, payload, datalen);

      if (strtoul(field_buffer(tcp_form[14], 0), NULL, 16))
         tcp->checksum = htons(strtoul(field_buffer(tcp_form[14], 0), NULL, 16));
      else
         tcp->checksum = Inet_Forge_Checksum( (u_short *)tcp, IPPROTO_TCP, TCP_HEADER+datalen, ip->source_ip, ip->dest_ip );

      len = TCP_HEADER + datalen;
   }

   for (c = 0; tcp_form[c] != 0; c++)
      free_field(tcp_form[c]);

   curs_set(0);

   return len;
}


int Interface_Factory_UDP(u_char *buf)
{
   WINDOW *w;
   FORM *form;
   FIELD *udp_form[14];
   int finished = 0, c;
   unsigned n = 0;
   short len = -1;

#ifdef DEBUG
   Debug_msg("Interface_Factory_UDP");
#endif

   refresh();

   udp_form[n++] = make_label(0, 18, "UDP Header");
   udp_form[n++] = make_label(0, 50, " ");
   udp_form[n++] = make_label(2, 0, "Source port :");
   udp_form[n++] = make_field(2, 14, 1, 5, FALSE);
   udp_form[n++] = make_label(2, 22, "Dest port   :");
   udp_form[n++] = make_field(2, 36, 1, 5, FALSE);
   udp_form[n++] = make_label(4, 0, "CheckSum : 0x");
   udp_form[n++] = make_field(4, 13, 1, 4, FALSE);
   udp_form[n++] = make_label(4, 20, "(leave blank for auto)");
   udp_form[n++] = make_label(6, 0, "Payload :");
   udp_form[n++] = make_field(7, 0, 8, 50, FALSE);
   udp_form[n++] = make_label(16, 0, "Or load Payload from file:");
   udp_form[n++] = make_field(17, 0, 1, 50, FALSE);
   udp_form[n++] = (FIELD *)0;


   form = new_form(udp_form);
   display_form(form);
   w = form_win(form);

   if (!Conn_Between_Hosts)
   {
      char port[5];
      snprintf(port, sizeof(port), "%d", Host_Source.port);
      set_field_buffer(udp_form[3], 0, port);
      snprintf(port, sizeof(port), "%d", Host_Dest.port);
      set_field_buffer(udp_form[5], 0, port);
   }
   else
   {
      char tmp[10];
      snprintf(tmp, sizeof(tmp), "%d", Conn_Between_Hosts[Conn_Pointer].source_port);
      set_field_buffer(udp_form[3], 0, tmp);
      snprintf(tmp, sizeof(tmp), "%d", Conn_Between_Hosts[Conn_Pointer].dest_port);
      set_field_buffer(udp_form[5], 0, tmp);
   }

   curs_set(1);
   //form_driver(form, REQ_OVL_MODE);

   finished = get_form_data(form, w);

   erase_form(form);
   free_form(form);

   if (finished == 2)
   {
      UDP_header *udp;
      IP_header *ip;
      u_char tmp[8*50 + 5];
      u_char payload[8*50];
      int datalen;

      ip = (IP_header *) (buf - IP_HEADER);     // we assume no IP Options !!
      udp = (UDP_header *) buf;

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, field_buffer(udp_form[12], 0), 50);
      trim_buffer(tmp, ' ');
      if (strlen(tmp) != 0)   // load from file
      {
         FILE *fts;
         fts = fopen(tmp, "r");
         if (!fts)
         {
            Interface_PopUp("File not found !!");
            return len;
         }
         fseek(fts, 0, SEEK_END);
         #ifdef DEBUG
            Debug_msg("Interface_Factory_UDP -- file opened [%s] size %d", tmp, ftell(fts));
         #endif
         if (ftell(fts) + 40 > 1500)
         {
            Interface_PopUp("File too big (max 1460 bytes)");
            return len;
         }
         rewind(fts);
         fgets(tmp, 1460, fts);
         datalen = FilterDrop_strescape(payload, tmp);
      }
      else
      {
         memset(tmp, 0, sizeof(tmp));
         memcpy(tmp, field_buffer(udp_form[10], 0), 8*50);
         trim_buffer(tmp, ' ');
         datalen = FilterDrop_strescape(payload, tmp);
      }

      udp->source      = htons(strtoul(field_buffer(udp_form[3], 0), NULL, 10));
      udp->dest        = htons(strtoul(field_buffer(udp_form[5], 0), NULL, 10));
      udp->checksum    = 0;
      udp->len         = htons(datalen + UDP_HEADER);

      #ifdef DEBUG
         Debug_msg("Interface_Factory_UDP -- [%d]", ntohs(udp->source));
         Debug_msg("Interface_Factory_UDP -- [%d]", ntohs(udp->dest));
      #endif

      ip->t_len        += htons(UDP_HEADER + datalen);
      if (!ip->checksum) ip->checksum = Inet_Forge_ChecksumIP( (u_short *)ip, sizeof(IP_header) );

      if (datalen)
         memcpy(buf + UDP_HEADER, payload, datalen);

      if (strtoul(field_buffer(udp_form[7], 0), NULL, 16))
         udp->checksum = htons(strtoul(field_buffer(udp_form[7], 0), NULL, 16));
      else
         udp->checksum = Inet_Forge_Checksum( (u_short *)udp, IPPROTO_UDP, UDP_HEADER+datalen, ip->source_ip, ip->dest_ip );

      len = UDP_HEADER + datalen;
   }

   for (c = 0; udp_form[c] != 0; c++)
      free_field(udp_form[c]);

   curs_set(0);

   return len;
}


int Interface_Factory_RAW(u_char *buf)
{
   WINDOW *w;
   FORM *form;
   FIELD *raw_form[7];
   int finished = 0, c;
   unsigned n = 0;
   short len = -1;

#ifdef DEBUG
   Debug_msg("Interface_Factory_RAW");
#endif

   refresh();

   raw_form[n++] = make_label(0, 18, "RAW data packet");
   raw_form[n++] = make_label(0, 50, " ");
   raw_form[n++] = make_label(2, 0, "Payload :");
   raw_form[n++] = make_field(3, 0, 14, 50, FALSE);
   raw_form[n++] = make_label(18, 0, "Or load Payload from file:");
   raw_form[n++] = make_field(19, 0, 1, 50, FALSE);
   raw_form[n++] = (FIELD *)0;


   form = new_form(raw_form);
   display_form(form);
   w = form_win(form);

   curs_set(1);
   //form_driver(form, REQ_OVL_MODE);

   finished = get_form_data(form, w);

   erase_form(form);
   free_form(form);

   if (finished == 2)
   {
      IP_header *ip;
      u_char tmp[14*50 + 5];
      u_char payload[14*50];
      int datalen;

      ip = (IP_header *) (buf - IP_HEADER);     // we assume no IP Options !!

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, field_buffer(raw_form[5], 0), 50);
      trim_buffer(tmp, ' ');
      if (strlen(tmp) != 0)   // load from file
      {
         FILE *fts;
         fts = fopen(tmp, "r");
         if (!fts)
         {
            Interface_PopUp("File not found !!");
            return len;
         }
         fseek(fts, 0, SEEK_END);
         #ifdef DEBUG
            Debug_msg("Interface_Factory_RAW -- file opened [%s] size %d", tmp, ftell(fts));
         #endif
         if (ftell(fts) + 40 > 1500)
         {
            Interface_PopUp("File too big (max 1460 bytes)");
            return len;
         }
         rewind(fts);
         fgets(tmp, 1460, fts);
         datalen = FilterDrop_strescape(payload, tmp);
      }
      else
      {
         memset(tmp, 0, sizeof(tmp));
         memcpy(tmp, field_buffer(raw_form[3], 0), 14*50);
         trim_buffer(tmp, ' ');
         datalen = FilterDrop_strescape(payload, tmp);
      }

      if (datalen)
         memcpy(buf, payload, datalen);

      ip->t_len += htons(datalen);
      if (!ip->checksum) ip->checksum = Inet_Forge_ChecksumIP( (u_short *)ip, sizeof(IP_header) );

      len = datalen;
   }

   for (c = 0; raw_form[c] != 0; c++)
      free_field(raw_form[c]);

   curs_set(0);

   return len;
}



#else    // DOESN'T HAVE FORM -----------------------------------------------------------------------------

int Interface_Factory_ETH(u_char *buf)
{

   WINDOW *w_factory, *f_win;
   int dimY = 10;
   int dimX = 35;
   char MACS[18], MACD[18];
   int len = -1;
   ETH_header *eth;

#ifdef DEBUG
   Debug_msg("Interface_Factory_ETH");
#endif

   f_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   w_factory = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(f_win, COLOR_PAIR(HELP_COLOR));
   wattron(f_win, A_BOLD);
   box(f_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(f_win,  0, 2, "Ethernet Header:", MAX_INJECT);
   wbkgdset(w_factory, COLOR_PAIR(BOTTOM_COLOR));
   wmove(w_factory, 0, 0);
   echo();
   scrollok(w_factory, TRUE);
   keypad(w_factory, TRUE);
   curs_set(TRUE);

   wprintw(w_factory, "\nEnter 'q' to exit...\n");

   wprintw(w_factory, "\nSource MAC : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, MACS, sizeof(MACS)-1);

   wprintw(w_factory, "\nDest MAC   : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, MACD, sizeof(MACD)-1);

   if ( MACS[0] == 'q' || MACD[0] == 'q')
   {
      curs_set(0);
      return -1;
   }

      eth = (ETH_header *) buf;

      if (Inet_GetMACfromString(MACS, eth->source_mac) == -1)
      {
         Interface_PopUp("Bad MAC parsing !! sould be in the form [01:02:03:04:05:06] !!");
         curs_set(0);
         return -1;
      }

      if (Inet_GetMACfromString(MACD, eth->dest_mac) == -1)
      {
         Interface_PopUp("Bad MAC parsing !! sould be in the form [01:02:03:04:05:06] !!");
         curs_set(0);
         return -1;
      }

      #ifdef DEBUG
         Debug_msg("Interface_Factory_ETH -- [%s]", MACS);
         Debug_msg("Interface_Factory_ETH -- [%s]", MACD);
      #endif

      eth->type = htons(ETH_P_IP);
      len = ETH_HEADER;

   noecho();
   curs_set(FALSE);
   delwin(f_win);
   delwin(w_factory);
   doupdate();

   return len;

}


int Interface_Factory_IP(u_char *buf, short *proto)
{

   WINDOW *w_factory, *f_win;
   int dimY = 15;
   int dimX = 45;
   char IPS[17], IPD[17];
   char ident[5];
   char protocol[3], TTL[3];
   char checksum[5];
   int len = -1;
   IP_header *ip;

#ifdef DEBUG
   Debug_msg("Interface_Factory_IP");
#endif

   f_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   w_factory = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(f_win, COLOR_PAIR(HELP_COLOR));
   wattron(f_win, A_BOLD);
   box(f_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(f_win,  0, 2, "IP Header:", MAX_INJECT);
   wbkgdset(w_factory, COLOR_PAIR(BOTTOM_COLOR));
   wmove(w_factory, 0, 0);
   echo();
   scrollok(w_factory, TRUE);
   keypad(w_factory, TRUE);
   curs_set(TRUE);

   wprintw(w_factory, "\nEnter 'q' to exit...\n");

   wprintw(w_factory, "\nSource IP : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, IPS, sizeof(IPS)-1);

   if ( IPS[0] == 'q' || IPS[0] == 'Q')
   {
      curs_set(0);
      return -1;
   }

   wprintw(w_factory, "\nDest IP   : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, IPD, sizeof(IPD)-1);

   if ( IPD[0] == 'q' || IPD[0] == 'Q')
   {
      curs_set(0);
      return -1;
   }

   wprintw(w_factory, "\nIdent : 0x");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, ident, sizeof(ident)-1);

   wprintw(w_factory, "\nTTL   : 0x");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, TTL, sizeof(TTL)-1);

   wprintw(w_factory, "\nProto (06 = TCP, 11 = UDP) : 0x");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, protocol, sizeof(protocol)-1);

   wprintw(w_factory, "\nChecksum (leave blank for auto) : 0x");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, checksum, sizeof(checksum)-1);

      ip = (IP_header *) buf;

      ip->h_len          = 5;
      ip->version        = 4;
      ip->tos            = 0;
      ip->t_len          = htons(IP_HEADER);    // to be calculated after payload len
      ip->ident          = htons(strtoul(ident, NULL, 16));
      ip->frag_and_flags = htons(0x4000);       // don't fragment
      ip->ttl            = strtoul(TTL, NULL, 16);
      ip->proto          = strtoul(protocol, NULL, 16);
      ip->checksum       = 0;                   // to be calculated after header completion
      ip->source_ip      = inet_addr(IPS);
      ip->dest_ip        = inet_addr(IPD);

      #ifdef DEBUG
         Debug_msg("Interface_Factory_IP -- [%s]", int_ntoa(ip->source_ip));
         Debug_msg("Interface_Factory_IP -- [%s]", int_ntoa(ip->dest_ip));
      #endif

      if (strtoul(checksum, NULL, 16))
         ip->checksum    = htons(strtoul(checksum, NULL, 16));

      *proto = ip->proto;
      len = IP_HEADER;

   noecho();
   curs_set(FALSE);
   delwin(f_win);
   delwin(w_factory);
   doupdate();

   return len;

}


int Interface_Factory_TCP(u_char *buf)
{
   WINDOW *w_factory, *f_win;
   int dimY = 15;
   int dimX = 45;
   char S[6], D[6];
   char seq[9], ack[9];
   char cflags[6];
   char checksum[5];
   int len = -1;
   int datalen, i;
   char flags = 0;
   IP_header *ip;
   TCP_header *tcp;
   u_char tmp[8*50 + 5];
   u_char payload[8*50];
   u_char file[50];

#ifdef DEBUG
   Debug_msg("Interface_Factory_TCP");
#endif

   f_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   w_factory = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(f_win, COLOR_PAIR(HELP_COLOR));
   wattron(f_win, A_BOLD);
   box(f_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(f_win,  0, 2, "TCP Header:", MAX_INJECT);
   wbkgdset(w_factory, COLOR_PAIR(BOTTOM_COLOR));
   wmove(w_factory, 0, 0);
   echo();
   scrollok(w_factory, TRUE);
   keypad(w_factory, TRUE);
   curs_set(TRUE);

   wprintw(w_factory, "\nEnter 'q' to exit...\n");

   wprintw(w_factory, "\nSource port : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, S, sizeof(S)-1);

   if ( S[0] == 'q' || S[0] == 'Q')
   {
      curs_set(0);
      return -1;
   }

   wprintw(w_factory, "\nDest port   : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, D, sizeof(D)-1);

   if ( D[0] == 'q' || D[0] == 'Q')
   {
      curs_set(0);
      return -1;
   }

   wprintw(w_factory, "\nSequence Number        : 0x");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, seq, sizeof(seq)-1);

   wprintw(w_factory, "\nAcknowledgement Number : 0x");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, ack, sizeof(ack)-1);

   wprintw(w_factory, "\nFlags (S/A/P/F/R) : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, cflags, sizeof(cflags)-1);

   wprintw(w_factory, "\nChecksum (leave blank for auto) : 0x");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, checksum, sizeof(checksum)-1);

   wprintw(w_factory, "\nPayload : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, payload, sizeof(payload));

   wprintw(w_factory, "\nOr load Payload from file : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, file, sizeof(file)-1);

      ip = (IP_header *) (buf - IP_HEADER);     // we assume no IP Options !!
      tcp = (TCP_header *) buf;

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, file, sizeof(file));
      if (strlen(tmp) != 0)   // load from file
      {
         FILE *fts;
         fts = fopen(tmp, "r");
         if (!fts)
         {
            Interface_PopUp("File not found !!");
            return len;
         }
         fseek(fts, 0, SEEK_END);
         #ifdef DEBUG
            Debug_msg("Interface_Factory_TCP -- file opened [%s] size %d", tmp, ftell(fts));
         #endif
         if (ftell(fts) + 40 > 1500)
         {
            Interface_PopUp("File too big (max 1460 bytes)");
            return len;
         }
         rewind(fts);
         fgets(tmp, 1460, fts);
         datalen = FilterDrop_strescape(payload, tmp);
      }
      else
      {
         memset(tmp, 0, sizeof(tmp));
         memcpy(tmp, payload, 8*50);
         datalen = FilterDrop_strescape(payload, tmp);
      }

      for(i=0; i<=strlen(cflags); i++)
         switch(cflags[i])
         {
            case 'A':
            case 'a':
                     flags |= TH_ACK;
                     break;
            case 'P':
            case 'p':
                     flags |= TH_PSH;
                     break;
            case 'F':
            case 'f':
                     flags |= TH_FIN;
                     break;
            case 'S':
            case 's':
                     flags |= TH_SYN;
                     break;
            case 'R':
            case 'r':
                     flags |= TH_RST;
                     break;
         }


      tcp->source      = htons(strtoul(S, NULL, 10));
      tcp->dest        = htons(strtoul(D, NULL, 10));
      tcp->seq         = htonl(strtoul(seq, NULL, 16));
      tcp->ack_seq     = htonl(strtoul(ack, NULL, 16));
      tcp->flags       = flags;
      tcp->unused      = 0;
      tcp->doff        = 5;
      tcp->window      = htons(32120);
      tcp->checksum    = 0;
      tcp->urg_ptr     = 0;

      #ifdef DEBUG
         Debug_msg("Interface_Factory_TCP -- [%d]", ntohs(tcp->source));
         Debug_msg("Interface_Factory_TCP -- [%d]", ntohs(tcp->dest));
      #endif

      ip->t_len        += htons(TCP_HEADER + datalen);
      if (!ip->checksum) ip->checksum = Inet_Forge_ChecksumIP( (u_short *)ip, sizeof(IP_header) );

      if (datalen)
         memcpy(buf + TCP_HEADER, payload, datalen);

      if (strtoul(checksum, NULL, 16))
         tcp->checksum = htons(strtoul(checksum, NULL, 16));
      else
         tcp->checksum = Inet_Forge_Checksum( (u_short *)tcp, IPPROTO_TCP, TCP_HEADER+datalen, ip->source_ip, ip->dest_ip );

      len = TCP_HEADER + datalen;

   noecho();
   curs_set(FALSE);
   delwin(f_win);
   delwin(w_factory);
   doupdate();

   return len;
}


int Interface_Factory_UDP(u_char *buf)
{
   WINDOW *w_factory, *f_win;
   int dimY = 15;
   int dimX = 45;
   char S[6], D[6];
   char checksum[5];
   int len = -1;
   int datalen;
   IP_header *ip;
   UDP_header *udp;
   u_char tmp[8*50 + 5];
   u_char payload[8*50];
   u_char file[50];

#ifdef DEBUG
   Debug_msg("Interface_Factory_UDP");
#endif

   f_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   w_factory = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(f_win, COLOR_PAIR(HELP_COLOR));
   wattron(f_win, A_BOLD);
   box(f_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(f_win,  0, 2, "UDP Header:", MAX_INJECT);
   wbkgdset(w_factory, COLOR_PAIR(BOTTOM_COLOR));
   wmove(w_factory, 0, 0);
   echo();
   scrollok(w_factory, TRUE);
   keypad(w_factory, TRUE);
   curs_set(TRUE);

   wprintw(w_factory, "\nEnter 'q' to exit...\n");

   wprintw(w_factory, "\nSource port : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, S, sizeof(S)-1);

   if ( S[0] == 'q' || S[0] == 'Q')
   {
      curs_set(0);
      return -1;
   }

   wprintw(w_factory, "\nDest port   : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, D, sizeof(D)-1);

   if ( D[0] == 'q' || D[0] == 'Q')
   {
      curs_set(0);
      return -1;
   }


   wprintw(w_factory, "\nChecksum (leave blank for auto) : 0x");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, checksum, sizeof(checksum)-1);

   wprintw(w_factory, "\nPayload : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, payload, sizeof(payload));

   wprintw(w_factory, "\nOr load Payload from file : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, file, sizeof(file)-1);

      ip = (IP_header *) (buf - IP_HEADER);     // we assume no IP Options !!
      udp = (UDP_header *) buf;

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, file, sizeof(file));
      if (strlen(tmp) != 0)   // load from file
      {
         FILE *fts;
         fts = fopen(tmp, "r");
         if (!fts)
         {
            Interface_PopUp("File not found !!");
            return len;
         }
         fseek(fts, 0, SEEK_END);
         #ifdef DEBUG
            Debug_msg("Interface_Factory_TCP -- file opened [%s] size %d", tmp, ftell(fts));
         #endif
         if (ftell(fts) + 40 > 1500)
         {
            Interface_PopUp("File too big (max 1460 bytes)");
            return len;
         }
         rewind(fts);
         fgets(tmp, 1460, fts);
         datalen = FilterDrop_strescape(payload, tmp);
      }
      else
      {
         memset(tmp, 0, sizeof(tmp));
         memcpy(tmp, payload, 8*50);
         datalen = FilterDrop_strescape(payload, tmp);
      }

      udp->source      = htons(strtoul(S, NULL, 10));
      udp->dest        = htons(strtoul(D, NULL, 10));
      udp->checksum    = 0;
      udp->len         = htons(datalen + UDP_HEADER);

      #ifdef DEBUG
         Debug_msg("Interface_Factory_UDP -- [%d]", ntohs(udp->source));
         Debug_msg("Interface_Factory_UDP -- [%d]", ntohs(udp->dest));
      #endif

      ip->t_len        += htons(UDP_HEADER + datalen);
      if (!ip->checksum) ip->checksum = Inet_Forge_ChecksumIP( (u_short *)ip, sizeof(IP_header) );

      if (datalen)
         memcpy(buf + UDP_HEADER, payload, datalen);

      if (strtoul(checksum, NULL, 16))
         udp->checksum = htons(strtoul(checksum, NULL, 16));
      else
         udp->checksum = Inet_Forge_Checksum( (u_short *)udp, IPPROTO_UDP, UDP_HEADER+datalen, ip->source_ip, ip->dest_ip );

      len = UDP_HEADER + datalen;

   noecho();
   curs_set(FALSE);
   delwin(f_win);
   delwin(w_factory);
   doupdate();

   return len;
}


int Interface_Factory_RAW(u_char *buf)
{
   WINDOW *w_factory, *f_win;
   int dimY = 15;
   int dimX = 45;
   int len = -1;
   int datalen;
   IP_header *ip;
   u_char tmp[14*50 + 5];
   u_char payload[14*50];
   u_char file[50];

#ifdef DEBUG
   Debug_msg("Interface_Factory_RAW");
#endif

   f_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   w_factory = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(f_win, COLOR_PAIR(HELP_COLOR));
   wattron(f_win, A_BOLD);
   box(f_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(f_win,  0, 2, "RAW Header:", MAX_INJECT);
   wbkgdset(w_factory, COLOR_PAIR(BOTTOM_COLOR));
   wmove(w_factory, 0, 0);
   echo();
   scrollok(w_factory, TRUE);
   keypad(w_factory, TRUE);
   curs_set(TRUE);

   wprintw(w_factory, "\nPayload : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, payload, sizeof(payload));

   wprintw(w_factory, "\nOr load Payload from file : ");
      wnoutrefresh(f_win);
      wnoutrefresh(w_factory);
      doupdate();
   wgetnstr(w_factory, file, sizeof(file)-1);

      ip = (IP_header *) (buf - IP_HEADER);     // we assume no IP Options !!

      memset(tmp, 0, sizeof(tmp));
      memcpy(tmp, file, sizeof(file));
      if (strlen(tmp) != 0)   // load from file
      {
         FILE *fts;
         fts = fopen(tmp, "r");
         if (!fts)
         {
            Interface_PopUp("File not found !!");
            return len;
         }
         fseek(fts, 0, SEEK_END);
         #ifdef DEBUG
            Debug_msg("Interface_Factory_TCP -- file opened [%s] size %d", tmp, ftell(fts));
         #endif
         if (ftell(fts) + 40 > 1500)
         {
            Interface_PopUp("File too big (max 1460 bytes)");
            return len;
         }
         rewind(fts);
         fgets(tmp, 1460, fts);
         datalen = FilterDrop_strescape(payload, tmp);
      }
      else
      {
         memset(tmp, 0, sizeof(tmp));
         memcpy(tmp, payload, 14*50);
         datalen = FilterDrop_strescape(payload, tmp);
      }

      if (datalen)
         memcpy(buf, payload, datalen);

      ip->t_len += htons(datalen);
      if (!ip->checksum) ip->checksum = Inet_Forge_ChecksumIP( (u_short *)ip, sizeof(IP_header) );

      len = datalen;

   noecho();
   curs_set(FALSE);
   delwin(f_win);
   delwin(w_factory);
   doupdate();

   return len;
}

#endif   // HAVE_FORM


int Interface_Factory_Run(void)
{

   u_char *buf;
   u_char *forged_pck;
   int ret = 0;
   int MTU, sock;
   short proto;

#ifdef DEBUG
   #ifdef HAVE_FORM
      Debug_msg("Interface_Factory_Run");
   #else
      Debug_msg("Interface_Factory_Run -- NO FORM");
   #endif
#endif

   sock = Inet_OpenRawSock(Options.netiface);

   Inet_GetIfaceInfo(Options.netiface, &MTU, NULL, NULL, NULL);

   buf = forged_pck = Inet_Forge_packet( MTU );

   if ( (ret = Interface_Factory_ETH( forged_pck )) > 0) forged_pck += ret;
   else goto cancelled;

   if ( (ret = Interface_Factory_IP( forged_pck, &proto )) > 0) forged_pck += ret;
   else goto cancelled;

   if (proto == IPPROTO_TCP)
   {
      if ( (ret = Interface_Factory_TCP( forged_pck )) > 0) forged_pck += ret;
      else goto cancelled;
   }
   else if (proto == IPPROTO_UDP)
   {
      if ( (ret = Interface_Factory_UDP( forged_pck )) > 0) forged_pck += ret;
      else goto cancelled;
   }
   else
   {
      if ( (ret = Interface_Factory_RAW( forged_pck )) >= 0) forged_pck += ret;
      else goto cancelled;
   }

   Inet_SendRawPacket(sock, buf, forged_pck-buf);

#ifdef DEBUG
   Debug_msg("Interface_Factory_Run -- %d byte(s) sent", forged_pck-buf);
#endif

   Interface_Redraw();
   Interface_PopUp("%d byte(s) forged and sent on the wire", forged_pck-buf);

cancelled:
#ifdef DEBUG
   Debug_msg("Interface_Factory_Run -- freeing buffer");
#endif
   Inet_Forge_packet_destroy( buf );
   Inet_CloseRawSock(sock);

   return 0;
}


#endif   // HAVE_NCURSES

/* EOF */

