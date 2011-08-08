/*
    ettercap -- ncurses interface for passive scanning of the LAN

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

    $Id: ec_interface_passive.c,v 1.14 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_NCURSES  // don't compile if ncurses interface is not supported

#ifdef HAVE_NCURSES_H
   #include <ncurses.h>
#else
   #include <curses.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include "include/ec_interface.h"
#include "include/ec_decodedata.h"
#include "include/ec_dryad.h"
#include "include/ec_inet.h"
#include "include/ec_inet_forge.h"
#include "include/ec_inet_structures.h"
#include "include/ec_buffer.h"
#include "include/ec_error.h"
#include "include/ec_logtofile.h"
#include "include/ec_fingerprint.h"
#include "include/ec_thread.h"


#define BOTTOM_COLOR  1        // color schemes
#define TITLE_COLOR   2
#define MAIN_COLOR    3
#define POINT_COLOR   4
#define SEL_COLOR     5
#define HELP_COLOR    6
#define SNIFF_COLOR   7
#define W_POINT_COLOR 8
#define W_MAIN_COLOR  9
#define N_MAIN_COLOR 10
#define N_POINT_COLOR 11

#define KEY_RETURN   10       // they aren't defined in ncurses.h :(
#define KEY_CTRL_L   12

#ifndef CTRL
#define CTRL(x)         ((x) & 0x1f)
#endif

#define KEY_QUIT            CTRL('q')
#define KEY_ESCAPE          CTRL('[')


// protos...
void Interface_Passive_Run(void);
void Interface_Passive_PointItem(char direction);
void Interface_Passive_InitList(void);
void Interface_Passive_RefreshList(void);
void Interface_Passive_MakeReport(char mode);
void Interface_Passive_ShowDetails(int i);
void Interface_Passive_Submit(int j);
void Interface_Passive_Showname(void);

// global variables

extern WINDOW *main_window, *bottom_window, *top_window;

extern int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2;
extern int W_BOTTOMX1, W_BOTTOMY1, W_BOTTOMX2, W_BOTTOMY2;
extern int W_SELECTCONN;

extern short LeftMargin;

int Host_Base_Pointer = 0;
int Host_Pointer = 0;
extern int Sel_Number;
char showname = 0;

//---------------------------


void Interface_Passive_InitList(void)
{
   int j;
   int Host_Top_Pointer;


   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
   else
      wattroff(main_window,A_REVERSE);

   werase(main_window);

   if (number_of_passive_hosts == 0)     // no connection... no action... ;)
   {
      wnoutrefresh(main_window);
      doupdate();
      return;
   }

   Host_Top_Pointer = (Host_Base_Pointer+Sel_Number < number_of_passive_hosts) ? Host_Base_Pointer + Sel_Number : number_of_passive_hosts ;

   for(j=Host_Base_Pointer; j<Host_Top_Pointer; j++)     // prints connections within the main_window height
   {
      if (!strcmp(Passive_Host[j].type, "GW"))
         wbkgdset(main_window, COLOR_PAIR(W_MAIN_COLOR));
      else if (!strcmp(Passive_Host[j].type, "NL"))
      {
         wattrset(main_window, A_BOLD);
         wbkgdset(main_window, COLOR_PAIR(N_MAIN_COLOR));
      }
      else
         wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));

      wmove(main_window, j-Host_Base_Pointer, LeftMargin );
      wprintw(main_window, "%3d) %-15s  ", j+1, (showname && strcmp(Passive_Host[j].name, "")) ? Passive_Host[j].name : Passive_Host[j].ip);
      wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
      wattroff(main_window, A_BOLD);
      wmove(main_window, j-Host_Base_Pointer, LeftMargin + 23);  waddch(main_window, ACS_VLINE);
      wprintw(main_window, " %2s ", Passive_Host[j].type);
      wmove(main_window, j-Host_Base_Pointer, LeftMargin + 28);  waddch(main_window, ACS_VLINE);
      wprintw(main_window, " %s", Passive_Host[j].os);
   }

   if (has_colors())
   {
      if (!strcmp(Passive_Host[Host_Pointer].type, "GW"))
         wbkgdset(main_window, COLOR_PAIR(W_POINT_COLOR));
      else if (!strcmp(Passive_Host[Host_Pointer].type, "NL"))
         wbkgdset(main_window, COLOR_PAIR(N_POINT_COLOR));
      else
         wbkgdset(main_window, COLOR_PAIR(POINT_COLOR));
   }
   else
      wattron(main_window,A_REVERSE);


   wmove(main_window, Host_Pointer - Host_Base_Pointer, LeftMargin );
   whline(main_window, ' ', W_SELECTCONN);
   wprintw(main_window, "%3d) %-15s  ", Host_Pointer+1, (showname && strcmp(Passive_Host[Host_Pointer].name, "")) ? Passive_Host[Host_Pointer].name : Passive_Host[Host_Pointer].ip);
   wbkgdset(main_window, COLOR_PAIR(POINT_COLOR));
   wmove(main_window, Host_Pointer-Host_Base_Pointer, LeftMargin + 23);  waddch(main_window, ACS_VLINE);
   wprintw(main_window, " %2s ",Passive_Host[Host_Pointer].type);
   wmove(main_window, Host_Pointer-Host_Base_Pointer, LeftMargin + 28);  waddch(main_window, ACS_VLINE);
   wprintw(main_window, " %s", Passive_Host[Host_Pointer].os);

   werase(bottom_window);
   if (Passive_Host[Host_Pointer].os[0] == 0 && Passive_Host[Host_Pointer].os[1] != 0)
   {
      wprintw(bottom_window, "UNKNOWN FINGERPRINT : %s\n",  Passive_Host[Host_Pointer].fingerprint);
      wprintw(bottom_window, "THE NEAREST IS      : %s", Passive_Host[Host_Pointer].os + 1);
   }



   wnoutrefresh(bottom_window);
   wnoutrefresh(main_window);
   doupdate();
}



void Interface_Passive_PointItem(char direction)
{

   int Old_Host_Pointer;

   if (number_of_passive_hosts == 0) return;   // no connection... no action... ;)

   Old_Host_Pointer = Host_Pointer;

   Host_Pointer += direction;

   if (Host_Pointer > number_of_passive_hosts -1 ) Host_Pointer = number_of_passive_hosts - 1;
   if (Host_Pointer < 0) Host_Pointer = 0;


   if ( (Host_Pointer - Host_Base_Pointer + direction  >= Sel_Number) && (direction > 0) )      // scroll down
   {
      if (Host_Base_Pointer + Sel_Number <= number_of_passive_hosts)
         Host_Base_Pointer = (Host_Base_Pointer + direction < number_of_passive_hosts) ? Host_Base_Pointer + direction : number_of_passive_hosts - Sel_Number;

      Interface_Passive_InitList();
   }
   else if ( (Host_Pointer - Host_Base_Pointer + direction < 0) && (direction < 0) )         // scroll up
   {
      if (Host_Base_Pointer > 0)
         Host_Base_Pointer = (Host_Base_Pointer + direction > 0) ? Host_Base_Pointer + direction : 0;

      Interface_Passive_InitList();
   }


   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
   else
      wattroff(main_window,A_REVERSE);


   if ( (Old_Host_Pointer >= Host_Base_Pointer) && (Old_Host_Pointer <= Host_Base_Pointer + Sel_Number -1)) // DON'T redraw previous selected item if it is out of view
   {
      if (!strcmp(Passive_Host[Old_Host_Pointer].type, "GW"))
         wbkgdset(main_window, COLOR_PAIR(W_MAIN_COLOR));
      else if (!strcmp(Passive_Host[Old_Host_Pointer].type, "NL"))
      {
         wattrset(main_window, A_BOLD);
         wbkgdset(main_window, COLOR_PAIR(N_MAIN_COLOR));
      }
      else
         wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));

      wmove(main_window, Old_Host_Pointer - Host_Base_Pointer, LeftMargin);
      whline(main_window,' ', W_SELECTCONN);                         //deletes the previous position
      wprintw(main_window, "%3d) %-15s  ", Old_Host_Pointer+1, (showname && strcmp(Passive_Host[Old_Host_Pointer].name, "")) ? Passive_Host[Old_Host_Pointer].name : Passive_Host[Old_Host_Pointer].ip);
      wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
      wattroff(main_window, A_BOLD);
      wmove(main_window, Old_Host_Pointer-Host_Base_Pointer, LeftMargin + 23);  waddch(main_window, ACS_VLINE);
      wprintw(main_window, " %2s ",Passive_Host[Old_Host_Pointer].type);
      wmove(main_window, Old_Host_Pointer-Host_Base_Pointer, LeftMargin + 28);  waddch(main_window, ACS_VLINE);
      wprintw(main_window, " %s", Passive_Host[Old_Host_Pointer].os);
   }

   if (has_colors())
   {
      if (!strcmp(Passive_Host[Host_Pointer].type, "GW"))
         wbkgdset(main_window, COLOR_PAIR(W_POINT_COLOR));
      else if (!strcmp(Passive_Host[Host_Pointer].type, "NL"))
         wbkgdset(main_window, COLOR_PAIR(N_POINT_COLOR));
      else
         wbkgdset(main_window, COLOR_PAIR(POINT_COLOR));
   }
   else
      wattron(main_window,A_REVERSE);

   wmove(main_window, Host_Pointer - Host_Base_Pointer, LeftMargin);
   whline(main_window, ' ', W_SELECTCONN);                           //select new position
   wprintw(main_window, "%3d) %-15s  ", Host_Pointer+1, (showname && strcmp(Passive_Host[Host_Pointer].name, "")) ? Passive_Host[Host_Pointer].name : Passive_Host[Host_Pointer].ip);
   wbkgdset(main_window, COLOR_PAIR(POINT_COLOR));
   wmove(main_window, Host_Pointer-Host_Base_Pointer, LeftMargin + 23);  waddch(main_window, ACS_VLINE);
   wprintw(main_window, " %2s ",Passive_Host[Host_Pointer].type);
   wmove(main_window, Host_Pointer-Host_Base_Pointer, LeftMargin + 28);  waddch(main_window, ACS_VLINE);
   wprintw(main_window, " %s", Passive_Host[Host_Pointer].os);

   werase(bottom_window);
   if (Passive_Host[Host_Pointer].os[0] == 0 && Passive_Host[Host_Pointer].os[1] != 0)
   {
      wprintw(bottom_window, "UNKNOWN FINGERPRINT : %s\n",  Passive_Host[Host_Pointer].fingerprint);
      wprintw(bottom_window, "THE NEAREST IS      : %s", Passive_Host[Host_Pointer].os + 1);
   }

   wnoutrefresh(bottom_window);
   wnoutrefresh(main_window);
   doupdate();
}



void Interface_Passive_MakeReport(char mode)
{
   char *file;
   WINDOW *message_window;
   char mess[17] = "making report...";

#ifdef DEBUG
   Debug_msg("Interface_Passive_MakeReport");
#endif

   message_window = newwin(5, strlen(mess) + 4,0,0);
   mvwin(message_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(mess) + 4)/2 );
   wbkgdset(message_window, COLOR_PAIR(TITLE_COLOR));
   wattron(message_window, A_BOLD);
   box(message_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(message_window,  2, 2, "%s", mess);
   wnoutrefresh(message_window);
   doupdate();

   Decodedata_Passive_SortList();
   file = LogToFile_MakePassiveReport(mode);

   delwin(message_window);
   touchwin(main_window);
   wnoutrefresh(main_window);
   doupdate();

   Interface_PopUp("Report stored in %s", file);

}



void Interface_Passive_ShowDetails(int i)
{
   WINDOW *detail_window, *d_win;
   int dimY = 17;
   int dimX = 75;
   int KeyPress;
   char found = 0;
   struct open_ports *current;

#ifdef DEBUG
   Debug_msg("Interface_Passive_ShowDetails");
#endif

   LIST_FOREACH(current, &Passive_Host[i].tcp_ports, next)    // enlarge the window to contain the open ports...
      if (current != LIST_FIRST(&Passive_Host[i].tcp_ports))
         dimY++;

   LIST_FOREACH(current, &Passive_Host[i].udp_ports, next)
      if (current != LIST_FIRST(&Passive_Host[i].udp_ports))
         dimY++;

   if (strcmp(Passive_Host[i].type, ""))
      dimY += 2;

   dimY = (dimY > W_BOTTOMY2-2) ? W_BOTTOMY2-2 : dimY;   // limit the window height

   d_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2 - 1, W_MAINX2/2 - dimX/2);
   detail_window = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(d_win, COLOR_PAIR(HELP_COLOR));
   wattron(d_win, A_BOLD);
   box(d_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(d_win,  0, 2, "Host Details :");
   wbkgdset(detail_window, COLOR_PAIR(BOTTOM_COLOR));
   wmove(detail_window, 0, 0);
   scrollok(detail_window, TRUE);

      wprintw(detail_window, "\n IP & MAC address    : %-15s%36s\n\n", Passive_Host[i].ip, Passive_Host[i].mac );

      wprintw(detail_window, " HOSTNAME            : %s\n\n", Inet_HostName(Passive_Host[i].ip));

      if (!strcmp(Passive_Host[i].type, "GW"))
         wprintw(detail_window, " **** THIS HOST IS A GATEWAY FOR IPs LIKE %s ****\n\n", Passive_Host[i].gwforthis);

      if (!strcmp(Passive_Host[i].type, "RT"))
         wprintw(detail_window, " **** THIS HOST ATCS AS A ROUTER FOR THE LAN ****\n\n");

      if (!strcmp(Passive_Host[i].type, "NL"))
         wprintw(detail_window, " **** THIS HOST DOESN'T BELONG TO THE NETMASK ****\n\n");

      if (Passive_Host[i].os[0] == 0 && Passive_Host[i].os[1] != 0)
      {
         wprintw(detail_window, " UNKNOWN FINGERPRINT : %s\n",  Passive_Host[i].fingerprint);
         wprintw(detail_window, " THE NEAREST IS      : %s\n", Passive_Host[i].os + 1);
         wprintw(detail_window, "                   --> press 'f' if you know the right OS <--\n\n");
      }
      else
      {
         wprintw(detail_window, " FINGERPRINT         : %s\n\n",  Passive_Host[i].fingerprint);
         wprintw(detail_window, " OPERATING SYSTEM    : %s\n\n",  Passive_Host[i].os);
      }

      wprintw(detail_window, " NETWORK ADAPTER     : %s\n\n",  Fingerprint_MAC(Passive_Host[i].mac));

      wprintw(detail_window, " DISTANCE IN HOP     : %d\n\n", Passive_Host[i].hop);

      if (!LIST_EMPTY(&Passive_Host[i].tcp_ports))
      {
         LIST_FOREACH(current, &Passive_Host[i].tcp_ports, next)
         {
            if (strcmp(current->banner, "")) found = 1;
            if (current == LIST_FIRST(&Passive_Host[i].tcp_ports))
               wprintw(detail_window, " OPEN PORTS  (tcp)   : %-5d  %s\n", current->port, Decodedata_GetType('T', current->port, current->port));
            else
               wprintw(detail_window, "                     : %-5d  %s\n", current->port, Decodedata_GetType('T', current->port, current->port));
         }
      }
      else
         wprintw(detail_window, " OPEN PORTS  (tcp)   : NONE\n");

      wprintw(detail_window, "\n");

      if (!LIST_EMPTY(&Passive_Host[i].udp_ports))
      {
         LIST_FOREACH(current, &Passive_Host[i].udp_ports, next)
         {
            if (current == LIST_FIRST(&Passive_Host[i].udp_ports))
               wprintw(detail_window, " OPEN PORTS  (udp)   : %-5d  %s\n", current->port, Decodedata_GetType('U', current->port, current->port) );
            else
               wprintw(detail_window, "                     : %-5d  %s\n", current->port, Decodedata_GetType('U', current->port, current->port) );
         }
      }
      else
         wprintw(detail_window, " OPEN PORTS  (udp)   : NONE\n");



   wnoutrefresh(d_win);
   wnoutrefresh(detail_window);
   doupdate();

   KeyPress = wgetch(detail_window);

   if (KeyPress == 'f' ||  KeyPress == 'F')
      Interface_Passive_Submit(i);

   if (found)
   {
      werase(detail_window);

      wprintw(detail_window, "\n TCP SERVICES BANNER : \n\n");

      if (!LIST_EMPTY(&Passive_Host[i].tcp_ports))
      {
         LIST_FOREACH(current, &Passive_Host[i].tcp_ports, next)
         {
            if (!strlen(current->banner)) continue;
            wprintw(detail_window, " %-5d  %s\n", current->port, current->banner );
         }
      }
      KeyPress = wgetch(detail_window);
   }

   delwin(d_win);
   delwin(detail_window);
   Interface_Redraw();
}



void Interface_Passive_Showname(void)
{
   if (showname)
   {
      showname = 0;
      Interface_Passive_InitList();
      return;
   }
   else
   {
      int i;
      WINDOW *message_window;
      char mess[23] = "resolving hostnames...";

      message_window = newwin(5, strlen(mess) + 4,0,0);
      mvwin(message_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(mess) + 4)/2 );
      wbkgdset(message_window, COLOR_PAIR(TITLE_COLOR));
      wattron(message_window, A_BOLD);
      box(message_window,ACS_VLINE,ACS_HLINE);
      mvwprintw(message_window,  2, 2, "%s", mess);
      wnoutrefresh(message_window);
      doupdate();

      showname = 1;
      for(i=0; i<number_of_passive_hosts; i++)
      {
         if ( !strcmp(Passive_Host[i].name, "") )
            strlcpy(Passive_Host[i].name, Inet_HostName(Passive_Host[i].ip), sizeof(Passive_Host[i].name));
      }

      delwin(message_window);
      touchwin(main_window);
      wnoutrefresh(main_window);
      doupdate();
   }
}


void Interface_Passive_Submit(int j)
{
   WINDOW *w_submit, *f_win;
   FILE *f_os, *f_temp;
   char *fingerprint, *ip;
   int dimY = 8;
   int dimX = 70;
   socket_handle sock;
   int i;
   char OS[60];
   char getmsg[500];
   char data[100];
   char host[] = "ettercap.sourceforge.net";
   char page[] = "/index.php?s=stuff&p=fingerprint";

#ifdef DEBUG
   Debug_msg("Interface_Passive_Submit -- [%s]", Passive_Host[j].fingerprint);
#endif

   fingerprint = strdup(Passive_Host[j].fingerprint);
   ip = strdup(Passive_Host[j].ip);

   f_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   w_submit = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(f_win, COLOR_PAIR(HELP_COLOR));
   wattron(f_win, A_BOLD);
   box(f_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(f_win,  0, 2, "Fingerprint submitter:    (press F10 to exit) ", MAX_INJECT);
   wbkgdset(w_submit, COLOR_PAIR(BOTTOM_COLOR));
   wmove(w_submit, 0, 0);
   scrollok(w_submit, TRUE);
   keypad(w_submit, TRUE);
   curs_set(TRUE);

   wprintw(w_submit, "\nYou are submitting a new fingerprint...\n");
   wprintw(w_submit, "\nPlease enter the Operating System of %s\nIts fingerprint is : %s\n\nOS: ", ip, fingerprint);
      wnoutrefresh(f_win);
      wnoutrefresh(w_submit);
      doupdate();

   memset(OS, 0, sizeof(OS));

   loop
   {
      int c = 0;
      static int p_text = 0;

      c = wgetch(w_submit);
      if ( c == 8 || c == 263 || c == KEY_BACKSPACE)  // BACKSPACE
      {
         int x=0,y=0;
         getyx(w_submit, y, x);
         wmove(w_submit, y, --x);
         pechochar(w_submit, ' ');
         wmove(w_submit, y, x);
         OS[p_text] = 0;
         if ( p_text > 0 ) p_text--;
      }
      else if ( c == KEY_F(10) || c == KEY_ESCAPE || c == KEY_QUIT )  // exit
      {
         curs_set(FALSE);
         delwin(f_win);
         delwin(w_submit);
         doupdate();
         return;
      }
      else
      {
         pechochar(w_submit, c);
         if (p_text < 60) OS[p_text++] = c;
      }

      if ( c == '\n')
      {
         OS[strlen(OS)-1] = 0;
         p_text = 0;
         break;
      }
   }

   curs_set(0);

   if ( !strcmp(OS, "") || !strcmp(fingerprint, "") )
      return;

#ifdef DEBUG
   Debug_msg("Interface_Passive_Submit - remote - %s %s", fingerprint, OS);
#endif

   for (i=0; i<60; i++)
      if (OS[i] == ' ') OS[i] = '+';

   snprintf(data, sizeof(data), "&finger=%s&os=%s", fingerprint, OS);

   werase(w_submit);
   wprintw(w_submit, "Connecting to http://%s...\n", host);
      wnoutrefresh(f_win);
      wnoutrefresh(w_submit);
      doupdate();

   sock = Inet_OpenSocket(host, 80);

   wprintw(w_submit, "Submitting the fingerprint to %s...\n\n", page);
      wnoutrefresh(f_win);
      wnoutrefresh(w_submit);
      doupdate();

   snprintf(getmsg, sizeof(getmsg), "GET %s%s HTTP/1.0\r\n"
                                    "Host: %s\r\n"
                                    "User-Agent: %s (%s).\r\n"
                                    "\r\n", page, data, host, PROGRAM, VERSION );

#ifdef DEBUG
   Debug_msg("Interface_Passive_Submit -- %s", getmsg);
#endif


   Inet_Http_Send(sock, getmsg);
   Inet_CloseSocket(sock);

   wprintw(w_submit, "\nNew fingerprint submitted to the ettercap website...\n");
      wnoutrefresh(f_win);
      wnoutrefresh(w_submit);
      doupdate();

   for (i=0; i<60; i++)
      if (OS[i] == '+') OS[i] = ' ';

   strlcpy(Passive_Host[j].os, OS, 60);

#ifdef DEBUG
   Debug_msg("Interface_Passive_Submit - local - [%s] [%s] [%s]", fingerprint, OS, Passive_Host[j].os);
#endif

   f_os = fopen( "./" OS_FILE, "r");
   if (f_os == NULL)
   {
      f_os = fopen( DATA_PATH "/" OS_FILE, "r");
      if (f_os == NULL)
         Error_msg("\nCan't find " OS_FILE " in ./ or " DATA_PATH);
   }

   f_temp = tmpfile();
   fchmod(fileno(f_temp), 0700);

   while(fgets (data, 99, f_os))
   {

      if ( strchr(data, '#') || !strlen(data))
      {
         fprintf(f_temp, "%s", data);
         continue;
      }

      if (strcmp(data, fingerprint) < 0)
         fprintf(f_temp, "%s", data);
      else
      {
         if (strlen(OS)) fprintf(f_temp, "%s:%.60s\n", fingerprint, OS);
         memset(OS, 0, sizeof(OS));
         fprintf(f_temp, "%s", data);
      }
   }
   rewind(f_temp);
   fclose(f_os);

   f_os = fopen( "./" OS_FILE, "w");
   if (f_os == NULL)
      f_os = fopen( DATA_PATH "/" OS_FILE, "w");

   while(fgets (data, 100, f_temp))
   {
      fprintf(f_os, "%s", data);
   }

   fclose(f_temp);
   fclose(f_os);

   wprintw(w_submit, "\nNew fingerprint added to the local database...");
      wnoutrefresh(f_win);
      wnoutrefresh(w_submit);
      doupdate();


   wgetch(w_submit);
   curs_set(FALSE);
   delwin(f_win);
   delwin(w_submit);
   doupdate();

   free(fingerprint);
   free(ip);

}



void Interface_Passive_Run(void)
{
   int KeyPress;
   pthread_t Dryad_pid;
   fd_set msk_fd;
   struct timeval TimeOut;

#ifdef DEBUG
   Debug_msg("Interface_Passive_Run");
#endif

   init_pair(W_MAIN_COLOR, COLOR_WHITE, COLOR_BLUE);
   init_pair(W_POINT_COLOR, COLOR_WHITE, COLOR_CYAN);
   init_pair(N_MAIN_COLOR, COLOR_BLACK, COLOR_BLUE);
   init_pair(N_POINT_COLOR, COLOR_BLACK, COLOR_CYAN);

   wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
   werase(main_window);
   werase(bottom_window);
   werase(top_window);

   wmove(top_window,0,0);
   wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
   wprintw(top_window, "SOURCE: ");
   wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
   wprintw(top_window, "%15s","  ANY  ");
   wmove(top_window,2,0);
   wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
   wprintw(top_window, "DEST  : ");
   wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
   wprintw(top_window, "%15s","  ANY  ");
   wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
   mvwprintw(top_window,0,25, "<"); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_URCORNER);
   wmove(top_window, 1,28); waddch(top_window, ACS_LTEE); waddch(top_window, ACS_HLINE);
   wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
   wprintw(top_window, " dryad (passive scanning) "); waddch(top_window, ACS_HLINE); wprintw(top_window, " %s", PROGRAM);
   wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
   mvwprintw(top_window,2,25, "<"); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_LRCORNER);
   wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));

   wmove(bottom_window, 0, 0);
   wnoutrefresh(main_window);
   wnoutrefresh(bottom_window);
   wnoutrefresh(top_window);
   doupdate();

   number_of_passive_hosts = 0;
   Interface_Passive_InitList();

   Dryad_pid = Dryad_Run();

   memset(&TimeOut, 0, sizeof(TimeOut));  //  timeout = 0
   FD_ZERO(&msk_fd);

   loop
   {
      FD_SET(0, &msk_fd);

      select(FOPEN_MAX, &msk_fd, (fd_set *) 0, (fd_set *) 0, &TimeOut);

      Interface_Passive_InitList();

      if (FD_ISSET(0, &msk_fd))
      {

         KeyPress = wgetch(main_window);

         switch (KeyPress)
         {
            case KEY_DOWN:
                     Interface_Passive_PointItem(1);
                     break;

            case KEY_UP:
                     Interface_Passive_PointItem(-1);
                     break;

            case KEY_NPAGE:
                     Interface_Passive_PointItem(Sel_Number-1);  //PGDOWN
                     break;

            case KEY_PPAGE:
                     Interface_Passive_PointItem(-Sel_Number+1); //PGUP
                     break;

            case KEY_RETURN:
                     if (Passive_Host[Host_Pointer].ip == NULL) break;   // no host
                     Interface_Passive_ShowDetails(Host_Pointer);
                     Interface_Passive_InitList();
                     break;

            case 'S':
            case 's':
                     Decodedata_Passive_SortList();
                     Interface_Passive_InitList();
                     break;

            case 'L':
            case 'l':
                     Interface_Passive_MakeReport(KeyPress);
                     break;

            case 'D':
            case 'd':
                     Interface_Passive_Showname();
                     break;


            case KEY_CTRL_L:  // CTRL+L refresh the screen
                     Interface_Redraw();
                     break;

            case KEY_F(1):
            case 'H':
            case 'h':{
                        static char *help[] = {
                           "[qQ][F10] - quit",
                           "[return]  - show detail for the selected host",
                           "[dD]      - toggle show name or IP",
                           "[l ]      - log collected info to a file (only local IP)",
                           "[L ]      - log all collected info to a file",
                           "[sS]      - sort the list",
                           "[cC]      - convert the list into the startup host list",
                           NULL};
                        Interface_HelpWindow(help);
                     }
                     Interface_Redraw();
                     break;

            case 'C':
            case 'c':
                     if (number_of_connections >= 0)
                     {
                        Interface_PopUp("Cannot convert form connection list interface");
                        break;
                     }
                     Decodedata_Passive_SortList();
                     Decodedata_ConvertPassiveToHost();
                     /* DON'T PUT BREAK HERE !!! we need to exit after this... */

            case 'Q':
            case 'q':
            case KEY_F(10):
                     ECThread_destroy(Dryad_pid);
                     werase(bottom_window);
                     werase(top_window);
                     wnoutrefresh(bottom_window);
                     wnoutrefresh(top_window);
                     doupdate();
                     Decodedata_FreePassiveList();
                     number_of_passive_hosts = -1;
                     Host_Pointer = 0;
                     showname = 0;
                     Options.passive = 0;
                     #ifdef DEBUG
                        Debug_msg("Interface_Passive_END");
                     #endif
                     return;
                     break;
         }
      }
      else
         usleep(1);
   }

}



#endif

/* EOF */
