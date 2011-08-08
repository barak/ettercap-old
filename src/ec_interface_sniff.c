/*
    ettercap -- ncurses interface for connection list

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

    $Id: ec_interface_sniff.c,v 1.13 2002/02/11 20:31:56 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_NCURSES  // don't compile if ncurses interface is not supported

#ifdef HAVE_NCURSES_H
   #include <ncurses.h>
#else
   #include <curses.h>
#endif

#include "include/ec_interface.h"
#include "include/ec_interface_sniff_data.h"
#include "include/ec_interface_factory.h"
#include "include/ec_interface_inject.h"
#include "include/ec_interface_passive.h"
#include "include/ec_filterdrop.h"
#include "include/ec_decodedata.h"
#include "include/ec_illithid.h"
#include "include/ec_doppleganger.h"
#include "include/ec_grell.h"
#include "include/ec_inet.h"
#include "include/ec_inet_forge.h"
#include "include/ec_inet_structures.h"
#include "include/ec_buffer.h"
#include "include/ec_error.h"
#include "include/ec_logtofile.h"
#include "include/ec_thread.h"

#ifdef PERMIT_PLUGINS
   #include "include/ec_interface_plugins.h"
   #include "include/ec_plugins.h"
#endif

#define BOTTOM_COLOR 1        // color schemes
#define TITLE_COLOR  2
#define MAIN_COLOR   3
#define POINT_COLOR  4
#define SEL_COLOR    5
#define HELP_COLOR   6
#define SNIFF_COLOR  7

#define KEY_RETURN   10       // they aren't defined in ncurses.h :(
#define KEY_CTRL_L   12


// protos...
void Interface_Sniff_Run(short mode);
void Interface_Sniff_PointItem(char direction);
void Interface_Sniff_InitList(void);
void Interface_Sniff_RefreshList(void);
void Interface_Sniff_KillConn(void);
void Interface_Sniff_ActiveDissecor(short mode);
void * Interface_Sniff_Timeouter(void *dummy);

// global variables

extern WINDOW *main_window, *bottom_window, *top_window;

extern int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2;
extern int W_BOTTOMX1, W_BOTTOMY1, W_BOTTOMX2, W_BOTTOMY2;
extern int W_SELECTCONN;

short LeftMargin = 0;

int Conn_Base_Pointer = 0;
int Conn_Pointer = 0;
extern int Sel_Number;

extern short inject;

//---------------------------


void Interface_Sniff_InitList(void)
{
   int j;
   int Conn_Top_Pointer;
   char info[250];

   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
   else
      wattroff(main_window,A_REVERSE);

   werase(main_window);

   if (number_of_connections == 0)     // no connection... no action... ;)
   {
      wnoutrefresh(main_window);
      doupdate();
      return;
   }

   Conn_Top_Pointer = (Conn_Base_Pointer+Sel_Number < number_of_connections) ? Conn_Base_Pointer + Sel_Number : number_of_connections ;

   for(j=Conn_Base_Pointer; j<Conn_Top_Pointer; j++)     // prints connections within the main_window height
   {
      wmove(main_window, j-Conn_Base_Pointer, LeftMargin );
      wprintw(main_window, "%3d) %15s:%d", j+1, Conn_Between_Hosts[j].source_ip, Conn_Between_Hosts[j].source_port);
      mvwprintw(main_window, j-Conn_Base_Pointer, 28," <--> %15s:%d", Conn_Between_Hosts[j].dest_ip , Conn_Between_Hosts[j].dest_port);
      wmove(main_window, j-Conn_Base_Pointer, LeftMargin + 56);  waddch(main_window, ACS_VLINE);
      wprintw(main_window, " %s", Conn_Between_Hosts[j].status);
      wmove(main_window, j-Conn_Base_Pointer, LeftMargin + 65);  waddch(main_window, ACS_VLINE);
      wprintw(main_window, " %s", Conn_Between_Hosts[j].type);
   }

   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(POINT_COLOR));
   else
      wattron(main_window,A_REVERSE);


   wmove(main_window, Conn_Pointer - Conn_Base_Pointer, LeftMargin );
   whline(main_window, ' ', W_SELECTCONN);
   wprintw(main_window, "%3d) %15s:%d", Conn_Pointer+1, Conn_Between_Hosts[Conn_Pointer].source_ip, Conn_Between_Hosts[Conn_Pointer].source_port);
   mvwprintw(main_window, Conn_Pointer-Conn_Base_Pointer, 28," <--> %15s:%d", Conn_Between_Hosts[Conn_Pointer].dest_ip , Conn_Between_Hosts[Conn_Pointer].dest_port);
   wmove(main_window, Conn_Pointer-Conn_Base_Pointer, LeftMargin + 56);  waddch(main_window, ACS_VLINE);
   wprintw(main_window, " %s", Conn_Between_Hosts[Conn_Pointer].status);
   wmove(main_window, Conn_Pointer - Conn_Base_Pointer, LeftMargin + 65); waddch(main_window, ACS_VLINE);
   wprintw(main_window, " %s", Conn_Between_Hosts[Conn_Pointer].type);

   werase(bottom_window);
   mvwprintw(bottom_window, 0, 1, " %s", Conn_Between_Hosts[Conn_Pointer].user);
   mvwprintw(bottom_window, 1, 1, " %s", Conn_Between_Hosts[Conn_Pointer].pass);
   snprintf(info, W_MAINX2 - 28, "%s", Conn_Between_Hosts[Conn_Pointer].info);
   if (strlen(info)+1 == W_MAINX2 - 28)
      mvwprintw(bottom_window, 1, 20, " %s->", info);
   else
      mvwprintw(bottom_window, 1, 20, " %s", info);

   wnoutrefresh(bottom_window);
   wnoutrefresh(main_window);
   doupdate();

}



void Interface_Sniff_PointItem(char direction)
{

   int Old_Conn_Pointer;
   char info[250];

   if (number_of_connections == 0) return;   // no connection... no action... ;)

   Old_Conn_Pointer = Conn_Pointer;

   Conn_Pointer += direction;

   if (Conn_Pointer > number_of_connections -1 ) Conn_Pointer = number_of_connections - 1;
   if (Conn_Pointer < 0) Conn_Pointer = 0;


   if ( (Conn_Pointer - Conn_Base_Pointer + direction  >= Sel_Number) && (direction > 0) )      // scroll down
   {
      if (Conn_Base_Pointer + Sel_Number <= number_of_connections)
         Conn_Base_Pointer = (Conn_Base_Pointer + direction < number_of_connections) ? Conn_Base_Pointer + direction : number_of_connections - Sel_Number;

      Interface_Sniff_InitList();
   }
   else if ( (Conn_Pointer - Conn_Base_Pointer + direction < 0) && (direction < 0) )         // scroll up
   {
      if (Conn_Base_Pointer > 0)
         Conn_Base_Pointer = (Conn_Base_Pointer + direction > 0) ? Conn_Base_Pointer + direction : 0;

      Interface_Sniff_InitList();
   }


   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
   else
      wattroff(main_window,A_REVERSE);


   if ( (Old_Conn_Pointer >= Conn_Base_Pointer) && (Old_Conn_Pointer <= Conn_Base_Pointer + Sel_Number -1)) // DON'T redraw previous selected item if it is out of view
   {
      wmove(main_window, Old_Conn_Pointer - Conn_Base_Pointer, LeftMargin);
      whline(main_window,' ', W_SELECTCONN);                         //deletes the previous position

      wprintw(main_window, "%3d) %15s:%d", Old_Conn_Pointer+1, Conn_Between_Hosts[Old_Conn_Pointer].source_ip, Conn_Between_Hosts[Old_Conn_Pointer].source_port);
      mvwprintw(main_window, Old_Conn_Pointer-Conn_Base_Pointer, 28," <--> %15s:%d", Conn_Between_Hosts[Old_Conn_Pointer].dest_ip , Conn_Between_Hosts[Old_Conn_Pointer].dest_port);
      wmove(main_window, Old_Conn_Pointer - Conn_Base_Pointer, LeftMargin + 56);  waddch(main_window, ACS_VLINE);
      wprintw(main_window, " %s", Conn_Between_Hosts[Old_Conn_Pointer].status);
      wmove(main_window, Old_Conn_Pointer - Conn_Base_Pointer, LeftMargin + 65);  waddch(main_window, ACS_VLINE);
      wprintw(main_window, " %s", Conn_Between_Hosts[Old_Conn_Pointer].type);
   }

   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(POINT_COLOR));
   else
      wattron(main_window,A_REVERSE);

   wmove(main_window, Conn_Pointer - Conn_Base_Pointer, LeftMargin);
   whline(main_window, ' ', W_SELECTCONN);                           //select new position

   wprintw(main_window, "%3d) %15s:%d", Conn_Pointer+1, Conn_Between_Hosts[Conn_Pointer].source_ip, Conn_Between_Hosts[Conn_Pointer].source_port);
   mvwprintw(main_window, Conn_Pointer-Conn_Base_Pointer, 28," <--> %15s:%d", Conn_Between_Hosts[Conn_Pointer].dest_ip , Conn_Between_Hosts[Conn_Pointer].dest_port);
   wmove(main_window, Conn_Pointer - Conn_Base_Pointer, LeftMargin + 56);  waddch(main_window, ACS_VLINE);
   wprintw(main_window, " %s", Conn_Between_Hosts[Conn_Pointer].status);
   wmove(main_window, Conn_Pointer - Conn_Base_Pointer, LeftMargin + 65);  waddch(main_window, ACS_VLINE);
   wprintw(main_window, " %s", Conn_Between_Hosts[Conn_Pointer].type);

   werase(bottom_window);
   mvwprintw(bottom_window, 0, 1, " %s", Conn_Between_Hosts[Conn_Pointer].user);
   mvwprintw(bottom_window, 1, 1, " %s", Conn_Between_Hosts[Conn_Pointer].pass);
   snprintf(info, W_MAINX2 - 28, "%s", Conn_Between_Hosts[Conn_Pointer].info);
   if (strlen(info)+1 == W_MAINX2 - 28)
      mvwprintw(bottom_window, 1, 20, " %s->", info);
   else
      mvwprintw(bottom_window, 1, 20, " %s", info);

   wnoutrefresh(bottom_window);
   wnoutrefresh(main_window);
   doupdate();
}



void Interface_Sniff_RefreshList(void)
{
   WINDOW *message_window;

#ifdef DEBUG
   Debug_msg("Interface_Sniff_RefreshList");
#endif

   message_window = newwin(5, strlen("updating list...") + 4,0,0);
   mvwin(message_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen("updating list...") + 4)/2 );
   wbkgdset(message_window, COLOR_PAIR(TITLE_COLOR));
   wattron(message_window, A_BOLD);
   box(message_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(message_window,  2, 2, "updating list...");
   wnoutrefresh(message_window);
   doupdate();

   Decodedata_RefreshConnectionList();
   Conn_Pointer = 0;
   Conn_Base_Pointer = 0;

   delwin(message_window);
   werase(bottom_window);
   wnoutrefresh(bottom_window);
   wnoutrefresh(main_window);

   doupdate();

#ifdef DEBUG
   Debug_msg("Interface_Sniff_RefreshList -- end");
#endif
}


void Interface_Sniff_KillConn(void)
{
   KILL_DATA kill_data;

   if (Conn_Between_Hosts[Conn_Pointer].proto == 'U')
   {
      Interface_PopUp("Trying to kill an UDP connection ?!? Ehi Kiddie, go home !!");
      return;
   }

#ifdef DEBUG
   Debug_msg("Interface_Sniff_KillConn -- %s:%d -> %s:%d ", Conn_Between_Hosts[Conn_Pointer].source_ip,
                                                            Conn_Between_Hosts[Conn_Pointer].source_port,
                                                            Conn_Between_Hosts[Conn_Pointer].dest_ip,
                                                            Conn_Between_Hosts[Conn_Pointer].dest_port );
#endif

   kill_data.source_ip = inet_addr(Conn_Between_Hosts[Conn_Pointer].source_ip);
   kill_data.dest_ip = inet_addr(Conn_Between_Hosts[Conn_Pointer].dest_ip);
   kill_data.source_port = htons(Conn_Between_Hosts[Conn_Pointer].source_port);
   kill_data.dest_port = htons(Conn_Between_Hosts[Conn_Pointer].dest_port);
   write(pipe_kill[1], &kill_data, sizeof(KILL_DATA));

   strcpy(Conn_Between_Hosts[Conn_Pointer].status, "KILLED");

}


void Interface_Sniff_ActiveDissecor(short mode)
{

#ifdef DEBUG
   Debug_msg("Interface_Sniff_ActiveDissecor %d", active_dissector);
#endif

   wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
   mvwprintw(top_window, 2, 31, "Active Dissector: ");

   switch(active_dissector)
   {
      case 1:  wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
               mvwprintw(top_window, 2, 49, "ON ");
               if (mode == PUBLICARP) wprintw(top_window," (only PUBLIC ARP)");
               break;

      case 0:  wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
               mvwprintw(top_window, 2, 49, "OFF");
               if (mode == PUBLICARP) wprintw(top_window," (only PUBLIC ARP)");
               break;
   }

   wnoutrefresh(top_window);
   doupdate();

}


void * Interface_Sniff_Timeouter(void *dummy)      // Timeouter thread
{
   int i;
   time_t now;
   extern pthread_mutex_t connection_mutex;

   loop
   {
      pthread_testcancel();

      if (number_of_connections <= 0)
      {
         usleep(5000);
         continue;
      }

      now = time(NULL);

      pthread_mutex_lock(&connection_mutex);

      for (i = 0; i < number_of_connections; i++)
      {
         if (Conn_Between_Hosts[i].proto == 'T')
         {
            if (!strcmp(Conn_Between_Hosts[i].status, "ACTIVE") && Conn_Between_Hosts[i].timestamp <= now - CONN_TIME_SILENT)
               strcpy(Conn_Between_Hosts[i].status, "silent");

            if (strcmp(Conn_Between_Hosts[i].status, "KILLED") &&
                strcmp(Conn_Between_Hosts[i].status, "CLOSED") && Conn_Between_Hosts[i].timestamp <= now - CONN_TIME_TIMEOUT) // 10 min of timeout
               strcpy(Conn_Between_Hosts[i].status, "timeout");
         }
      }

      pthread_mutex_unlock(&connection_mutex);

      sleep(2);
   }
}



void Interface_Sniff_Run(short mode)
{
   int KeyPress, i;
   pthread_t Illithid_pid = 0, Dopple_pid = 0, time_pid = 0;
   #if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
      pthread_t Grell_pid = 0;
   #endif
   fd_set msk_fd;
   struct timeval TimeOut;

#ifdef DEBUG
   Debug_msg("Interface_Sniff_Run -- mode %d", mode);
#endif

   if (pipe_with_illithid_data == -1) pipe_with_illithid_data = Buffer_Create(1.0e6);
   if (pipe_with_plugins == -1) pipe_with_plugins = Buffer_Create(1.5e5);  // 150 Kbyte

   wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
   werase(main_window);
   werase(bottom_window);

   wmove(bottom_window, 0, 0);
   wnoutrefresh(main_window);
   wnoutrefresh(bottom_window);
   doupdate();

   if (mode > PUBLICARP )
      active_dissector = 0;

   Interface_Sniff_ActiveDissecor(mode);
   Interface_Inject_FilterTopStatus();

   number_of_connections = 0;
   Interface_Sniff_RefreshList();
   Interface_Sniff_InitList();

   switch (mode)
   {
      case ARPBASED:
      case PUBLICARP:
                     Inet_DisableForwarding();

                     for(i=0; i<number_of_hosts_in_lan; i++)
                     {
                        if ( !strcmp(Host_Source.ip, Host_In_LAN[i].ip) )
                           strlcpy(Host_Source.mac, Host_In_LAN[i].mac, sizeof(Host_Source.mac));
                        if ( !strcmp(Host_Dest.ip, Host_In_LAN[i].ip) )
                           strlcpy(Host_Dest.mac, Host_In_LAN[i].mac, sizeof(Host_Dest.mac));
                     }

                     if ( !strcmp(Host_Source.mac, "") && !strcmp(Host_Dest.mac, "") )
                        Error_msg("Doppelganger needs at least one valid mac address !!\n\n(the ip was not found in the list)");

                     Dopple_pid = Doppleganger_Run(Options.netiface, Host_Source.ip, Host_Dest.ip, Host_Source.mac, Host_Dest.mac);

                     if ( mode == ARPBASED )
                        Illithid_pid = Illithid_ARPBased_GetConnections(Options.netiface, Host_Source.ip, Host_Dest.ip, Host_Source.mac, Host_Dest.mac);
                     else
                        Illithid_pid = Illithid_PublicARP_GetConnections(Options.netiface, Host_Source.ip, Host_Dest.ip, Host_Source.mac, Host_Dest.mac);

                     #if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
                        Grell_pid = Grell_Run();
                     #endif

                     break;
      case IPBASED:
                     Illithid_pid = Illithid_IPBased_GetConnections(Options.netiface, Host_Source.ip, Host_Dest.ip);
                     break;
      case MACBASED:
                     Illithid_pid = Illithid_MACBased_GetConnections(Options.netiface, Host_Source.mac, Host_Dest.mac);
                     break;
   }

   if (Options.passive) Interface_Passive_Run();

   memset(&TimeOut, 0, sizeof(TimeOut));  //  timeout = 0
   FD_ZERO(&msk_fd);

   time_pid = ECThread_create("timeouter", &Interface_Sniff_Timeouter, NULL);

   loop
   {
      FD_SET(0, &msk_fd);

      select(FOPEN_MAX, &msk_fd, (fd_set *) 0, (fd_set *) 0, &TimeOut);

      Interface_Sniff_InitList();

#ifdef PERMIT_PLUGINS
      Interface_Plugins_PluginOutput();
#endif

      if (FD_ISSET(0, &msk_fd))
      {

#ifdef PERMIT_PLUGINS
         Interface_Plugins_HidePluginOutput();
#endif

         KeyPress = wgetch(main_window);

         switch (KeyPress)
         {
            case KEY_DOWN:
                     Interface_Sniff_PointItem(1);
                     break;

            case KEY_UP:
                     Interface_Sniff_PointItem(-1);
                     break;

            case KEY_NPAGE:
                     Interface_Sniff_PointItem(Sel_Number-1);  //PGDOWN
                     break;

            case KEY_PPAGE:
                     Interface_Sniff_PointItem(-Sel_Number+1); //PGUP
                     break;

            case KEY_RETURN:
                     if (Conn_Between_Hosts[Conn_Pointer].source_ip == NULL) break;   // no connections
                     wmove(bottom_window, 0, 0);
                     mvwprintw(top_window, 2, 52, "                    ");

                     Connection_Mode = 0;

                     Interface_Sniff_Data_Run(Conn_Between_Hosts[Conn_Pointer].source_ip,
                                              Conn_Between_Hosts[Conn_Pointer].source_port,
                                              Conn_Between_Hosts[Conn_Pointer].dest_ip,
                                              Conn_Between_Hosts[Conn_Pointer].dest_port,
                                              Conn_Between_Hosts[Conn_Pointer].source_mac,
                                              Conn_Between_Hosts[Conn_Pointer].dest_mac,
                                              Conn_Between_Hosts[Conn_Pointer].proto,
                                              Conn_Between_Hosts[Conn_Pointer].type,
                                              mode);
                     // wait and then...
                     Connection_Mode = 1;

                     Interface_Sniff_ActiveDissecor(mode);
                     if (filter_on_source && FilterDrop_CheckMode(Filter_Array_Source, mode))
                     {
                        Interface_PopUp("The Source filter chain can be used only in ARPBASED mode !!");
                        filter_on_source = 0;
                        Interface_Inject_FilterStatus();
                     }
                     if (filter_on_dest && FilterDrop_CheckMode(Filter_Array_Dest, mode))
                     {
                        Interface_PopUp("The Dest filter chain can be used only in ARPBASED mode !!");
                        filter_on_dest = 0;
                        Interface_Inject_FilterStatus();
                     }
                     Interface_Sniff_InitList();
                     break;

            case 'K':
            case 'k':
                     if (Conn_Between_Hosts[Conn_Pointer].source_ip == NULL) break;   // no connections
                     Interface_Sniff_KillConn();      // with TH_RST !  i'm too tired to implement FIN handshaking
                     Interface_Sniff_InitList();
                     break;

            case 'D':
            case 'd':
                     {
                        char source[40];
                        char dest[40];
                        if (Conn_Between_Hosts[Conn_Pointer].source_ip == NULL) break;   // no connections
                        snprintf(source, 39, " %s (%s) <-->", Inet_HostName(Conn_Between_Hosts[Conn_Pointer].source_ip),
                                                              Conn_Between_Hosts[Conn_Pointer].source_ip);
                        snprintf(dest, 39, " %s (%s)", Inet_HostName(Conn_Between_Hosts[Conn_Pointer].dest_ip),
                                                       Conn_Between_Hosts[Conn_Pointer].dest_ip);
                        source[39] = dest[39] = 0;
                        Interface_PopUp("%s%s", source, dest);
                     }
                     break;

            case 'R':
            case 'r':
                     Interface_Sniff_RefreshList();
                     Interface_Sniff_InitList();
                     break;

            case 'X':
            case 'x':
                     Interface_Factory_Run();
                     Interface_Redraw();
                     break;

            case 'L':
            case 'l':
                     Interface_PopUp("Passwords dumped to %s", LogToFile_DumpPass());
                     break;

#ifdef PERMIT_PLUGINS
            case 'P':
            case 'p':
                     Interface_Plugins_Run();
                     Buffer_Flush(pipe_with_plugins);
                     break;

            case 'I':
            case 'i':
                     Interface_Plugins_Output();
                     Interface_Redraw();
                     break;
#endif

            case 'A':
            case 'a':
                     if (mode <= PUBLICARP)
                     {
                        active_dissector = (active_dissector) ? 0 : 1;     // activate/deactivate active dissector (arp based)
                        #ifdef DEBUG
                           Debug_msg("\tactive_dissector %d", active_dissector);
                        #endif
                        Interface_Sniff_ActiveDissecor(mode);
                     }
                     else
                     {
                        Interface_PopUp("ACTIVE dissector is available only in ARP mode !!");
                     }
                     break;

            case 'F':
            case 'f':
                     Interface_Inject_SetFilter(mode);
                     Interface_Redraw();
                     break;

            case 'O':
            case 'o':
                     Interface_Passive_Run();
                     Interface_Sniff_InitList();
                     break;

            case KEY_CTRL_L:  // CTRL+L refresh the screen
                     Interface_Redraw();
                     break;

            case KEY_F(1):
            case 'H':
            case 'h':{
                        static char *help[] = {
                           "[qQ][F10] - quit",
                           "[return]  - sniff the selected connection",
                           "[xX]      - Packet Forge",
                           "[aA]      - enable/disable ACTIVE password collectors",
                           "[fF]      - set/edit filters chains",
                           "[lL]      - log all collected passwords to a file",
                           "[kK]      - kill the connection (be careful !)",
#ifdef PERMIT_PLUGINS
                           "[pP]      - plugin management",
                           "[iI]      - plugin output window",
#endif
                           "[oO]      - passive scanning of the LAN",
                           "[dD]      - resolve ip via DNS",
                           "[rR]      - refresh the list",
                           NULL};
                        Interface_HelpWindow(help);
                     }
                     Interface_Redraw();
                     break;

            case 'Q':
            case 'q':
                     if (inject == 1)
                     {
                        char answer;
                        answer = Interface_PopUp("If U exit now some connections may be ReSeTted!! continue (y/n)?");
                        Interface_Redraw();
                        if ((answer != 'y') && (answer != 'Y'))
                           break;
                     }
                     {
                        WINDOW *message_window;
                        char mess[29] = "shutting down all threads...";

                        message_window = newwin(5, strlen(mess) + 4,0,0);
                        mvwin(message_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(mess) + 4)/2 );
                        wbkgdset(message_window, COLOR_PAIR(TITLE_COLOR));
                        wattron(message_window, A_BOLD);
                        box(message_window,ACS_VLINE,ACS_HLINE);
                        mvwprintw(message_window,  2, 2, "%s", mess);
                        wnoutrefresh(message_window);
                        doupdate();

                        ECThread_destroy(Illithid_pid);
                        ECThread_destroy(time_pid);
                        if (Dopple_pid) ECThread_destroy(Dopple_pid);
                        #if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
                           if (Grell_pid) ECThread_destroy(Grell_pid);
                        #endif
                        delwin(message_window);
                        touchwin(main_window);
                        wnoutrefresh(main_window);
                        inject = 0;
                     }
                     #ifdef DEBUG
                        Debug_msg("Interface_Sniff_END");
                     #endif
                     if (Options.silent) Interface_WExit("They are safe!!  for now... ");
                     werase(bottom_window);
                     wnoutrefresh(bottom_window);
                     doupdate();
                     Decodedata_RefreshConnectionList();
                     number_of_connections = -1;
                     return;
                     break;

            case KEY_F(10):
                     #ifdef DEBUG
                        Debug_msg("Interface_Sniff_END");
                        Debug_msg("Interface_Run_END");
                     #endif
                     {
                        WINDOW *message_window;
                        char mess[29] = "shutting down all threads...";

                        message_window = newwin(5, strlen(mess) + 4,0,0);
                        mvwin(message_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(mess) + 4)/2 );
                        wbkgdset(message_window, COLOR_PAIR(TITLE_COLOR));
                        wattron(message_window, A_BOLD);
                        box(message_window,ACS_VLINE,ACS_HLINE);
                        mvwprintw(message_window,  2, 2, "%s", mess);
                        wnoutrefresh(message_window);
                        doupdate();

                        ECThread_destroy(Illithid_pid);
                        ECThread_destroy(time_pid);
                        if (Dopple_pid) ECThread_destroy(Dopple_pid);
                        #if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
                           if (Grell_pid) ECThread_destroy(Grell_pid);
                        #endif
                        delwin(message_window);
                        touchwin(main_window);
                        wnoutrefresh(main_window);
                     }
                     Interface_WExit("They are safe!!  for now... ");
                     break;
         }
      }
      else  // workaround for the 100% CPU usage...
         usleep(1);

   }

}



#endif

/* EOF */
