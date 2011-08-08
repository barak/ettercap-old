/*
    ettercap -- ncurses main interface

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

    $Id: ec_interface.c,v 1.11 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_NCURSES  // don't compile if ncurses interface is not supported

#ifdef HAVE_NCURSES_H
   #include <ncurses.h>
#else
   #include <curses.h>
#endif

#include <stdarg.h>

#if defined (HAVE_TERMIOS_H) && !defined(CYGWIN)
   #include <termios.h>
   struct termios original_term_info;
#endif

#include "include/ec_interface_sniff.h"
#include "include/ec_interface_passive.h"
#include "include/ec_interface_factory.h"
#include "include/ec_inet.h"
#include "include/ec_buffer.h"
#include "include/ec_fingerprint.h"
#include "include/ec_error.h"


#ifdef PERMIT_PLUGINS
   #include "include/ec_interface_plugins.h"
   #include "include/ec_plugins.h"
#endif

#define DOWN   +1             // movements for the pointer
#define UP     -1
#define RIGHT  +1
#define LEFT   -1

#define BOTTOM_COLOR 1        // color schemes
#define TITLE_COLOR  2
#define MAIN_COLOR   3
#define POINT_COLOR  4
#define SEL_COLOR    5
#define HELP_COLOR   6

#define KEY_TAB      '\t'     // they aren't defined in ncurses.h :(
#define KEY_RETURN   10
#define KEY_CTRL_L   12

// Graphic Macros

#define CENTER(p1,p2,len) p1 + ((unsigned)((p2-p1)/2) - (unsigned)(len/2))


// prototyping...

void Interface_InitTitle(char *ip, char *mac, char *subnet);
void Interface_InitScreen(void);
void Interface_CloseScreen(void);
void Interface_Winch(void);
void Interface_Redraw(void);
void Interface_WExit(char *buffer);
void Interface_Run(void);
void Interface_GetWindowSize(void);
void Interface_PointItem(char direction, char hor_direction);
void Interface_InitList(void);
void Interface_KeyTab(void);
void Interface_SelectItem(void);
void Interface_Connect(void);
char Interface_PopUp(char *question, ...);
void Interface_RefreshList(void);
void Interface_HelpWindow(char *help[]);
void Interface_OldStyleSniff(short mode);
void Interface_CheckForPoisoner(void);
void Interface_FingerPrint(void);
void Interface_EntryRemoval(void);

// global variables for Interface...

int W_BOTTOMX1, W_BOTTOMY1, W_BOTTOMX2, W_BOTTOMY2;
int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2;
int W_TOPX1, W_TOPY1, W_TOPX2, W_TOPY2;
int W_SELECTX, W_SELECTCONN, W_SELECTPLUG;
int W_LIST_SOURCE, W_LIST_DEST;

int Base_Pointer = 0;
int Source_Pointer = 0;
int Dest_Pointer = 0;
int *Pointer = &Source_Pointer;
int Sel_Number;

// int sel_for_source = -1, sel_for_dest = -1;  TODO color selection

WINDOW *main_window, *bottom_window, *top_window, *b_main_window, *b_bottom_window, *b_top_window;

char title_bottom_window[100];
char title_main_window[100];
char title_top_window[100];

short ScreenMode;

// -------------------------------------------

void Interface_GetWindowSize(void)
{

   W_BOTTOMX1 = 0;
   W_BOTTOMY1 = LINES - 4;
   W_BOTTOMX2 = COLS - 1;
   W_BOTTOMY2 = LINES;

   W_MAINX1 = 0;
   W_MAINX2 = COLS - 1;
   W_MAINY2 = W_BOTTOMY1 - 1;

   W_TOPX1 = 0;
   W_TOPY1 = 0;
   W_TOPX2 = COLS - 1;

   W_TOPY2 = W_TOPY1 + 4;
   W_MAINY1 = W_TOPY2 + 1;


   W_SELECTX = 25;
   W_LIST_SOURCE = (W_MAINX2 - W_SELECTX * 2)/2 ;
   W_LIST_DEST = W_LIST_SOURCE + W_SELECTX;

   Sel_Number = W_MAINY2 - W_MAINY1 - 1;

   W_SELECTCONN = W_MAINX2 - 1;

   W_SELECTPLUG = W_SELECTCONN - 5;

#ifdef DEBUG
   Debug_msg("Interface_GetWindowSize");
#endif
}



void Interface_Winch(void)       // TODO better handling...
{
#ifdef DEBUG
   Debug_msg("Interface_Winch\tTODO");
#endif
/*
   clear();

   Interface_GetWindowSize();


   delwin(main_window); delwin(b_main_window);
   delwin(top_window); delwin(b_top_window);
   delwin(bottom_window); delwin(b_bottom_window);

   b_main_window = newwin(W_MAINY2 - W_MAINY1 + 1, W_MAINX2 - W_MAINX1 + 1, W_MAINY1, W_MAINX1);
   b_bottom_window  = newwin(W_BOTTOMY2 - W_BOTTOMY1, W_BOTTOMX2 - W_BOTTOMX1 + 1, W_BOTTOMY1, W_BOTTOMX1);
   b_top_window = newwin(W_TOPY2 - W_TOPY1 + 1, W_TOPX2 - W_TOPX1 + 1, W_TOPY1, W_TOPX1);

   main_window = newwin(W_MAINY2 - W_MAINY1 - 1, W_MAINX2 - W_MAINX1 - 1, W_MAINY1 + 1, W_MAINX1 + 1);
   bottom_window = newwin(W_BOTTOMY2 - W_BOTTOMY1 - 2, W_BOTTOMX2 - W_BOTTOMX1 - 1, W_BOTTOMY1 + 1, W_BOTTOMX1 + 1);
   top_window = newwin(W_TOPY2 - W_TOPY1 - 1, W_TOPX2 - W_TOPX1 - 1, W_TOPY1 + 1, W_TOPX1 + 1);


   keypad(main_window, 1);
*/

// Interface_GetWindowSize();
// resizeterm( W_BOTTOMY2, W_MAINX2 +1);
   Interface_Redraw();

}


void Interface_Redraw(void)
{
#ifdef DEBUG
   Debug_msg("Interface_Redraw");
#endif

   clear();

   box(b_main_window,ACS_VLINE,ACS_HLINE);
   box(b_bottom_window,ACS_VLINE,ACS_HLINE);
   box(b_top_window,ACS_VLINE,ACS_HLINE);

   wbkgdset(b_main_window, COLOR_PAIR(TITLE_COLOR)); wattron(b_main_window, A_BOLD);
   wbkgdset(b_top_window, COLOR_PAIR(TITLE_COLOR)); wattron(b_top_window, A_BOLD);
   wbkgdset(b_bottom_window, COLOR_PAIR(TITLE_COLOR)); wattron(b_bottom_window, A_BOLD);

   mvwprintw(b_main_window, 0, CENTER(W_MAINX1, W_MAINX2, strlen(title_main_window)), "%s", title_main_window);
   mvwprintw(b_bottom_window, 0, CENTER(W_BOTTOMX1, W_BOTTOMX2, strlen(title_bottom_window)), "%s", title_bottom_window);
   mvwprintw(b_top_window, 0, CENTER(W_TOPX1, W_TOPX2, strlen(title_top_window)), "%s", title_top_window);

   wbkgdset(b_main_window, COLOR_PAIR(BOTTOM_COLOR)); wattroff(b_main_window, A_BOLD);
   wbkgdset(b_top_window, COLOR_PAIR(BOTTOM_COLOR)); wattroff(b_top_window, A_BOLD);
   wbkgdset(b_bottom_window, COLOR_PAIR(BOTTOM_COLOR)); wattroff(b_bottom_window, A_BOLD);

   redrawwin(stdscr);
   redrawwin(b_main_window);
   redrawwin(b_bottom_window);
   redrawwin(b_top_window);
   redrawwin(main_window);
   redrawwin(bottom_window);
   redrawwin(top_window);

   wnoutrefresh(stdscr);
   wnoutrefresh(b_main_window);
   wnoutrefresh(b_bottom_window);
   wnoutrefresh(b_top_window);
   wnoutrefresh(main_window);
   wnoutrefresh(bottom_window);
   wnoutrefresh(top_window);

   doupdate();

}






void Interface_InitTitle(char *ip, char *mac, char *subnet)
{
#ifdef DEBUG
   Debug_msg("Interface_InitTitle [%s] [%s] [%s]", ip, mac, subnet);
#endif

   if (Options.silent)
   {
      snprintf(title_main_window, 100, " ??? hosts in this LAN (%s : %s) ", ip, subnet);
      snprintf(title_bottom_window, 100, " Your IP: %s MAC: %s Iface: %s Link: not tested", ip, mac, Options.netiface);
   }
   else
   {
      char link_type[10];
      short type;

      switch(type = Inet_CheckSwitch())
      {
         case 0: strcpy(link_type, "unknown");
                 break;
         case 1: strcpy(link_type, "HUB");
                 break;
         case 2: strcpy(link_type, "SWITCH");
                 break;
      }
      snprintf(title_main_window, 100, " %3d hosts in this LAN (%s : %s) ", number_of_hosts_in_lan, ip, subnet);
      snprintf(title_bottom_window, 100, " Your IP: %s MAC: %s Iface: %s Link: %s ", ip, mac, Options.netiface, link_type);
   }
   snprintf(title_top_window, 100, " %s %s ", PROGRAM, VERSION);

}



void Interface_InitScreen(void)
{
#ifdef DEBUG
   Debug_msg("Interface_InitScreen");
#endif

#if defined (HAVE_TERMIOS_H) && !defined(CYGWIN)
   tcgetattr(0, &original_term_info);
#endif

   initscr();
   cbreak();
   noecho();

#ifdef CYGWIN
   LINES = 25;
   COLS = 80;
#endif

#ifdef DEBUG
   Debug_msg("Interface_InitScreen -- screen size %dx%d", LINES, COLS);
#endif

   ScreenMode = 1;

   Interface_GetWindowSize();

   if (has_colors()) start_color();

   curs_set(0);         // hide the cursor

   init_pair(TITLE_COLOR, COLOR_YELLOW, COLOR_BLACK);
   init_pair(MAIN_COLOR, COLOR_CYAN, COLOR_BLUE);
   init_pair(BOTTOM_COLOR, COLOR_WHITE, COLOR_BLACK);
   init_pair(POINT_COLOR, COLOR_BLUE, COLOR_CYAN);
   init_pair(HELP_COLOR, COLOR_CYAN, COLOR_BLACK);
   init_pair(SEL_COLOR, COLOR_WHITE, COLOR_BLUE);     // TODO choose the color

   b_main_window = newwin(W_MAINY2 - W_MAINY1 + 1, W_MAINX2 - W_MAINX1 + 1, W_MAINY1, W_MAINX1);
   b_bottom_window  = newwin(W_BOTTOMY2 - W_BOTTOMY1, W_BOTTOMX2 - W_BOTTOMX1 + 1, W_BOTTOMY1, W_BOTTOMX1);
   b_top_window = newwin(W_TOPY2 - W_TOPY1 + 1, W_TOPX2 - W_TOPX1 + 1, W_TOPY1, W_TOPX1);

   main_window = newwin(W_MAINY2 - W_MAINY1 - 1, W_MAINX2 - W_MAINX1 - 1, W_MAINY1 + 1, W_MAINX1 + 1);
   bottom_window = newwin(W_BOTTOMY2 - W_BOTTOMY1 - 2, W_BOTTOMX2 - W_BOTTOMX1 - 1, W_BOTTOMY1 + 1, W_BOTTOMX1 + 1);
   top_window = newwin(W_TOPY2 - W_TOPY1 - 1, W_TOPX2 - W_TOPX1 - 1, W_TOPY1 + 1, W_TOPX1 + 1);


   wmove(bottom_window, 0, 0);
   wmove(main_window, 0, 0);
   wmove(top_window, 0, 0);


   wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));     // sets the colors
   wbkgdset(b_main_window, COLOR_PAIR(BOTTOM_COLOR));
   wbkgdset(bottom_window, COLOR_PAIR(BOTTOM_COLOR));
   wbkgdset(b_bottom_window, COLOR_PAIR(BOTTOM_COLOR));
   wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
   wbkgdset(b_top_window, COLOR_PAIR(BOTTOM_COLOR));

   werase(top_window);
   werase(bottom_window);
   werase(main_window);

#ifndef CYGWIN
   wattrset(bottom_window, A_BOLD);
#endif

   keypad(main_window,1);

#ifdef DEBUG
   Debug_msg("Interface_InitScreen -- INIZIALIZED");
#endif

   Interface_Redraw();     // touch the screen and call doupdate()
   Interface_InitList();

}


void Interface_InitList(void)
{
   int j;
   int Top_Pointer;

   if (number_of_hosts_in_lan == 0) return;

   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
   else
      wattroff(main_window,A_REVERSE);
   werase(main_window);

   Top_Pointer = (Base_Pointer+Sel_Number < number_of_hosts_in_lan) ? Base_Pointer + Sel_Number : number_of_hosts_in_lan ;

   for(j=Base_Pointer; j<Top_Pointer; j++)      // prints IPs within the main_window height
   {
      wmove(main_window, j-Base_Pointer, W_LIST_SOURCE );

      //if (sel_for_source == j) wbkgdset(main_window, COLOR_PAIR(SEL_COLOR));      // TODO  color selection
      //else if (sel_for_dest == j) wbkgdset(main_window, COLOR_PAIR(SEL_COLOR));
      //else wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));

      wprintw(main_window, "%3d) %15s      %3d) %15s", j+1, Host_In_LAN[j].ip, j+1, Host_In_LAN[j].ip);
   }

   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(POINT_COLOR));
   else
      wattron(main_window,A_REVERSE);


   if (Pointer == &Source_Pointer)
   {
      wmove(main_window, *Pointer - Base_Pointer, W_LIST_SOURCE );
      whline(main_window, ' ', W_SELECTX);
      wprintw(main_window,"%3d) %15s", *Pointer+1, Host_In_LAN[*Pointer].ip);
      wmove(bottom_window,0,0); whline(bottom_window, ' ', W_BOTTOMX2);
      mvwprintw(bottom_window, 0, 2, "Host: %s (%s) : %s", Host_In_LAN[*Pointer].name, Host_In_LAN[*Pointer].ip, Host_In_LAN[*Pointer].mac);
   }
   else if (Pointer == &Dest_Pointer)
   {
      wmove(main_window, *Pointer - Base_Pointer, W_LIST_DEST );
      whline(main_window, ' ', W_SELECTX);
      wprintw(main_window, " %3d) %15s", *Pointer+1, Host_In_LAN[*Pointer].ip);
      wmove(bottom_window,1,0); whline(bottom_window, ' ', W_BOTTOMX2);
      mvwprintw(bottom_window, 1, 2, "Host: %s (%s) : %s", Host_In_LAN[*Pointer].name, Host_In_LAN[*Pointer].ip, Host_In_LAN[*Pointer].mac);
   }

   touchwin(bottom_window);
   touchwin(main_window);
   wnoutrefresh(bottom_window);
   wnoutrefresh(main_window);
   doupdate();
}



void Interface_PointItem(char direction, char hor_direction)
{

   int Old_Pointer;

   Old_Pointer = *Pointer;

   *Pointer += direction;

   if (*Pointer > number_of_hosts_in_lan -1 ) *Pointer = number_of_hosts_in_lan - 1;
   if (*Pointer < 0) *Pointer = 0;


   if ( (*Pointer - Base_Pointer + direction  >= Sel_Number) && (direction > 0) )      // scroll down
   {
      if (Base_Pointer + Sel_Number <= number_of_hosts_in_lan)
         Base_Pointer = (Base_Pointer + direction < number_of_hosts_in_lan) ? Base_Pointer + direction : number_of_hosts_in_lan - Sel_Number;

      Interface_InitList();
   }
   else if ( (*Pointer - Base_Pointer + direction < 0) && (direction < 0) )         // scroll up
   {
      if (Base_Pointer > 0)
         Base_Pointer = (Base_Pointer + direction > 0) ? Base_Pointer + direction : 0;

      Interface_InitList();
   }


   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));
   else
      wattroff(main_window,A_REVERSE);

   if (hor_direction)
   {
      switch(hor_direction)
      {
         case LEFT:
                     if (Pointer == &Dest_Pointer)
                     {
                        Pointer = &Source_Pointer;
                        *Pointer = Dest_Pointer;
                     }
                     break;
         case RIGHT:
                     if (Pointer == &Source_Pointer)
                     {
                        Pointer = &Dest_Pointer;
                        *Pointer = Source_Pointer;
                     }
                     break;
      }
   }

   if ( (Old_Pointer >= Base_Pointer) && (Old_Pointer <= Base_Pointer + Sel_Number -1))   // DON'T redraw previous selected item if it is out of view
   {
      wmove(main_window, Old_Pointer - Base_Pointer, W_LIST_SOURCE);
      whline(main_window,' ',W_MAINX2 - 1);                          //deletes the previous position
      wprintw(main_window, "%3d) %15s      %3d) %15s", Old_Pointer+1, Host_In_LAN[Old_Pointer].ip, Old_Pointer+1, Host_In_LAN[Old_Pointer].ip);
   }

   if (has_colors())
      wbkgdset(main_window, COLOR_PAIR(POINT_COLOR));
   else
      wattron(main_window,A_REVERSE);

   if (Pointer == &Source_Pointer)
   {
      wmove(main_window, *Pointer - Base_Pointer, W_LIST_SOURCE);
      whline(main_window, ' ', W_SELECTX);                           //select new position
      wprintw(main_window, "%3d) %15s", *Pointer+1, Host_In_LAN[*Pointer].ip);
      wmove(bottom_window,0,0); whline(bottom_window, ' ', W_BOTTOMX2);
      mvwprintw(bottom_window, 0, 2, "Host: %s (%s) : %s", Host_In_LAN[*Pointer].name, Host_In_LAN[*Pointer].ip, Host_In_LAN[*Pointer].mac);

   }
   else if (Pointer == &Dest_Pointer)
   {
      wmove(main_window, *Pointer - Base_Pointer, W_LIST_DEST);
      whline(main_window, ' ', W_SELECTX);                           //select new position
      wprintw(main_window, " %3d) %15s", *Pointer+1, Host_In_LAN[*Pointer].ip);
      wmove(bottom_window,1,0); whline(bottom_window, ' ', W_BOTTOMX2);
      mvwprintw(bottom_window, 1, 2, "Host: %s (%s) : %s", Host_In_LAN[*Pointer].name, Host_In_LAN[*Pointer].ip, Host_In_LAN[*Pointer].mac);
   }


   touchwin(bottom_window);
   touchwin(main_window);
   wnoutrefresh(bottom_window);
   wnoutrefresh(main_window);
   doupdate();
}



void Interface_KeyTab(void)
{

   if (Pointer == &Source_Pointer)
   {

      while (Dest_Pointer < Base_Pointer)
         Base_Pointer = (Base_Pointer - Sel_Number > 0) ? (Base_Pointer - Sel_Number) : 0;

      while (Dest_Pointer > Base_Pointer + Sel_Number -1)
         Base_Pointer = (Base_Pointer + Sel_Number < number_of_hosts_in_lan) ? (Base_Pointer + Sel_Number) : number_of_hosts_in_lan - Sel_Number;

      Pointer = &Dest_Pointer;
   }
   else
   {
      while (Source_Pointer < Base_Pointer)
         Base_Pointer = (Base_Pointer - Sel_Number > 0) ? (Base_Pointer - Sel_Number) : 0;

      while (Source_Pointer > Base_Pointer + Sel_Number -1)
         Base_Pointer = (Base_Pointer + Sel_Number < number_of_hosts_in_lan) ? (Base_Pointer + Sel_Number) : number_of_hosts_in_lan - Sel_Number;

      Pointer = &Source_Pointer;
   }

}



void Interface_SelectItem(void)        // TODO  implement color selection
{
#ifdef DEBUG
   Debug_msg("Interface_SelectItem");
#endif


   if (Pointer == &Source_Pointer)
   {
      wmove(top_window,0,0); whline(top_window, ' ', W_TOPX2);
      wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
      wprintw(top_window, "SOURCE: ");
      wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
      wprintw(top_window, "%15s", Host_In_LAN[Source_Pointer].ip);
      memcpy(&Host_Source, &Host_In_LAN[Source_Pointer], sizeof(HOST) );
      //sel_for_source = *Pointer;
   }
   else
   {
      wmove(top_window,2,0); whline(top_window, ' ', W_TOPX2);
      wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
      wprintw(top_window, "DEST  : ");
      wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
      wprintw(top_window, "%15s", Host_In_LAN[Dest_Pointer].ip);
      memcpy(&Host_Dest, &Host_In_LAN[Dest_Pointer], sizeof(HOST) );
      //sel_for_dest = *Pointer;
   }

   touchwin(top_window);
   wnoutrefresh(top_window);
   doupdate();

}



char Interface_PopUp(char *question, ...)
{
   WINDOW *question_window;
   char answer;
   char message[150];
   va_list ap;

   va_start(ap, question);
   vsnprintf(message, 150, question, ap);
   va_end(ap);

   question_window = newwin(5, strlen(message) + 4,0,0);
   mvwin(question_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(message)+4)/2 + 2 );
   wbkgdset(question_window, COLOR_PAIR(TITLE_COLOR));
   wattron(question_window, A_BOLD);
   box(question_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(question_window,  2, 2, "%s", message);
   wnoutrefresh(question_window);
   doupdate();
   answer = wgetch(question_window);
   delwin(question_window);
   touchwin(main_window);
   wnoutrefresh(main_window);

   doupdate();

#ifdef DEBUG
   Debug_msg("Interface_PopUp returns -- %c", answer);
#endif

   return answer;
}



void Interface_RefreshList(void)
{
   WINDOW *message_window;
   char mess[21] = "updating the list...";

#ifdef DEBUG
   Debug_msg("Interface_RefreshList");
#endif

   message_window = newwin(5, strlen(mess) + 4,0,0);
   mvwin(message_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(mess) + 4)/2 );
   wbkgdset(message_window, COLOR_PAIR(TITLE_COLOR));
   wattron(message_window, A_BOLD);
   box(message_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(message_window,  2, 2, "%s", mess);
   wnoutrefresh(message_window);
   doupdate();

   number_of_hosts_in_lan = Inet_HostInLAN();
   Source_Pointer = Dest_Pointer = 0;
   Base_Pointer = 0;
   sprintf(title_main_window, "%3d", number_of_hosts_in_lan);     // devil workaround ;)
   title_main_window[3] = ' ';

   delwin(message_window);
   touchwin(main_window);
   wnoutrefresh(main_window);

   doupdate();

}


void Interface_HelpWindow(char *help[])
{
   WINDOW *help_window;
   int i = 2, y = 0,  max = 0;
   char **counter;
   int dimY = 0;
   int dimX = 0;

   for (counter = help; *counter; counter++)
   {
         max = (strlen(*counter) > max) ? strlen(*counter) : max;
         y++;
   }

   dimY = y + 4;
   dimX = max + 4;

   help_window = newwin(dimY, dimX,0,0);
   mvwin(help_window, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   wbkgdset(help_window, COLOR_PAIR(HELP_COLOR));
   wattron(help_window, A_BOLD);
   box(help_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(help_window, 0, 1, "Help Window");

   for (counter = help; *counter; counter++)
   {
      mvwprintw(help_window, i++, 2, "%s", *counter);
   }

   wnoutrefresh(help_window);
   doupdate();
   wgetch(help_window);
   delwin(help_window);

}



void Interface_Connect(void)
{

#ifdef DEBUG
   Debug_msg("Interface_Connect");
#endif

   if ( (!strcmp(Host_Source.ip, "")) && (!strcmp(Host_Dest.ip, "")) )
      Interface_PopUp("Before sniffing select AT LEAST source OR destination !!");
   else if ( (!strcmp(Host_Source.ip, Inet_MyIPAddress())) || (!strcmp(Host_Dest.ip, Inet_MyIPAddress())) )
      Interface_PopUp("You CAN'T arpsniff yourself !!");
   else if ( !strcmp(Host_Source.ip, Host_Dest.ip) )
      Interface_PopUp("SOURCE and DEST must be different !!");
   else
   {
      char answer;

      if (Options.silent || Options.arpsniff)  answer = 'y';
      else answer = Interface_PopUp("Do U really want to poison the ARP cache of the targets (y/n) ?");

      if ((answer == 'y') || (answer == 'Y'))
      {
         wmove(top_window,0,0); whline(top_window, ' ', W_TOPX2);
         wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
         wprintw(top_window, "SOURCE: ");
         wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));

         if (strcmp(Host_Source.ip,""))
            wprintw(top_window, "%15s", Host_Source.ip);
         else
            wprintw(top_window, "%15s","  ANY  ");

         wmove(top_window,2,0); whline(top_window, ' ', W_TOPX2);
         wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
         wprintw(top_window, "DEST  : ");
         wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));

         if (strcmp(Host_Dest.ip,""))
            wprintw(top_window, "%15s", Host_Dest.ip);
         else
            wprintw(top_window, "%15s","  ANY  ");

         wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
         mvwprintw(top_window,0,25, "<"); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_URCORNER);
         wmove(top_window, 1,28); waddch(top_window, ACS_LTEE); waddch(top_window, ACS_HLINE);
         wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
         wprintw(top_window, " doppleganger "); waddch(top_window, ACS_HLINE);

         if ( number_of_hosts_in_lan == 1 && ((!strcmp(Host_Source.ip, "")) || (!strcmp(Host_Dest.ip, ""))) )
            wprintw(top_window, " illithid (Public ARP) ");
         else
            wprintw(top_window, " illithid (ARP Based) ");

         waddch(top_window, ACS_HLINE);
         wprintw(top_window, " %s", PROGRAM);
         wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
         mvwprintw(top_window,2,25, "<"); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_LRCORNER);
         wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
         wnoutrefresh(top_window);

         if ( number_of_hosts_in_lan == 1 && ((!strcmp(Host_Source.ip, "")) || (!strcmp(Host_Dest.ip, ""))) )
            Interface_Sniff_Run(PUBLICARP);   // with HALF duplex ARP poisoning
         else
            Interface_Sniff_Run(ARPBASED);   // with FULL duplex ARP poisoning

         // wait for return, than...
         memset(&Host_Source, 0, sizeof(HOST) );
         memset(&Host_Dest, 0, sizeof(HOST) );
         werase(top_window);
         wnoutrefresh(top_window);
         Interface_InitList();
      }
   }

   doupdate();
}



void Interface_OldStyleSniff(short mode)
{

#ifdef DEBUG
   Debug_msg("Interface_OldStyleSniff -- mode = %d", mode);
#endif

   if ( !strcmp(Host_Source.ip, Host_Dest.ip) && strcmp(Host_Source.ip, "") )
      Interface_PopUp("SOURCE and DEST must be different !!");
   else if ( !strcmp(Host_Source.mac, Host_Dest.mac) && strcmp(Host_Source.mac, ""))
      Interface_PopUp("SOURCE and DEST must be different !!");
   else
   {
      wmove(top_window,0,0); whline(top_window, ' ', W_TOPX2);
      wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
      wprintw(top_window, "SOURCE: ");
      wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));

      if (mode)
      {
         if (strcmp(Host_Source.mac, ""))
            wprintw(top_window, "%15s", Host_Source.mac);
         else
            wprintw(top_window, "%15s","  ANY  ");
      }
      else
      {
         if (strcmp(Host_Source.ip, ""))
            wprintw(top_window, "%15s", Host_Source.ip);
         else
            wprintw(top_window, "%15s","  ANY  ");
      }

      wmove(top_window,2,0); whline(top_window, ' ', W_TOPX2);
      wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
      wprintw(top_window, "DEST  : ");
      wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));

      if (mode)
      {
         if (strcmp(Host_Dest.mac, ""))
            wprintw(top_window, "%15s", Host_Dest.mac);
         else
            wprintw(top_window, "%15s","  ANY  ");
      }
      else
      {
         if (strcmp(Host_Dest.ip, ""))
            wprintw(top_window, "%15s", Host_Dest.ip);
         else
            wprintw(top_window, "%15s","  ANY  ");
      }

      wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
      mvwprintw(top_window,0,25, "<"); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_URCORNER);
      if (mode)
      {
         wmove(top_window, 1,28); waddch(top_window, ACS_LTEE); waddch(top_window, ACS_HLINE);
         wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
         wprintw(top_window, " illithid (MAC based) "); waddch(top_window, ACS_HLINE); wprintw(top_window, " %s", PROGRAM);
      }
      else
      {
         wmove(top_window, 1,28); waddch(top_window, ACS_LTEE); waddch(top_window, ACS_HLINE);
         wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
         wprintw(top_window, " illithid (IP based) "); waddch(top_window, ACS_HLINE); wprintw(top_window, " %s", PROGRAM);
      }
      wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
      mvwprintw(top_window,2,25, "<"); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_HLINE); waddch(top_window, ACS_LRCORNER);
      wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
      wnoutrefresh(top_window);

      if (mode)
         Interface_Sniff_Run(MACBASED);   // no ARP poisoning
      else
         Interface_Sniff_Run(IPBASED);    // no ARP poisoning

      // wait for return, then...
      memset(&Host_Source, 0, sizeof(HOST) );
      memset(&Host_Dest, 0, sizeof(HOST) );
      werase(top_window);
      wnoutrefresh(top_window);
      Interface_InitList();

   }

   doupdate();
}


void Interface_CheckForPoisoner(void)
{
   WINDOW *message_window;
   SniffingHost *SniffList;
   int i;
   short found = 0;
   char mess[26] = "checking for poisoners...";

#ifdef DEBUG
   Debug_msg("Interface_CheckForPoisoner");
#endif

   if (number_of_hosts_in_lan == 1)
   {
      Interface_PopUp("You cannot check the lan in silent mode");
      return;
   }

   message_window = newwin(5, strlen(mess) + 4,0,0);
   mvwin(message_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(mess) + 4)/2 );
   wbkgdset(message_window, COLOR_PAIR(TITLE_COLOR));
   wattron(message_window, A_BOLD);
   box(message_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(message_window,  2, 2, "%s", mess);
   wnoutrefresh(message_window);
   doupdate();

   SniffList = Inet_NoSniff();

   for (i=0; i<number_of_hosts_in_lan; i++)
   {
      if (SniffList[i].mode == 0) break;
      if (SniffList[i].mode == 1)
      {
         found = 1;
         Interface_PopUp("%s is replying for %s", Host_In_LAN[SniffList[i].Host_Index1].ip, Host_In_LAN[SniffList[i].Host_Index2].ip);
      }

      if (SniffList[i].mode == 2)
      {
         found = 1;
         Interface_PopUp("MAC of %s and %s are identical !",Host_In_LAN[SniffList[i].Host_Index1].ip,Host_In_LAN[SniffList[i].Host_Index2].ip);
      }
   }

   if (!found)
      Interface_PopUp("No poisoners found in this lan (seems to be safe)");

   free(SniffList);
   delwin(message_window);
   touchwin(main_window);
   wnoutrefresh(main_window);
   doupdate();

}



void Interface_FingerPrint(void)
{
   WINDOW *finger_win;
   WINDOW *message_window;
   int dimY = 7;
   int dimX = 20;
   int i=0, j=0, k=0;
   char mess[20] = "Fingerprinting ...";
   char *mac_finger;
   char *long_os_fingers;
   char temp[W_MAINX2];

#ifdef DEBUG
   Debug_msg("Interface_FingerPrint -- [%s] [%s]", Host_In_LAN[*Pointer].ip, Host_In_LAN[*Pointer].mac );
#endif

   message_window = newwin(5, strlen(mess) + 4,0,0);
   mvwin(message_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(mess) + 4)/2 );
   wbkgdset(message_window, COLOR_PAIR(TITLE_COLOR));
   wattron(message_window, A_BOLD);
   box(message_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(message_window,  2, 2, "%s", mess);
   wnoutrefresh(message_window);
   doupdate();

   long_os_fingers = strdup(Fingerprint_OS(Host_In_LAN[*Pointer].ip) );
   mac_finger = strdup(Fingerprint_MAC(Host_In_LAN[*Pointer].mac));

   if (strlen(mac_finger)> W_MAINX2-4-18 ) mac_finger[W_MAINX2-4-18] = 0;

   delwin(message_window);
   touchwin(main_window);
   wnoutrefresh(main_window);
   doupdate();

   for(i=0; i <= strlen(long_os_fingers); i++)
   {
      if (long_os_fingers[i] == '\n')
      {
         dimY++;
         j++;
         dimX = (i-k > dimX) ? i-k : dimX;   // length of the max string
         k=i;
      }
   }

   dimX = (strlen(mac_finger)>dimX) ? strlen(mac_finger) : dimX;
   dimX = (dimX + 27 < W_MAINX2-1) ? dimX + 27 : W_MAINX2-1;

   finger_win = newwin(dimY, dimX, 0, 0);
   mvwin(finger_win, W_BOTTOMY2/2 - dimY/2, (W_MAINX2/2 - dimX/2) + 1);
   wbkgdset(finger_win, COLOR_PAIR(TITLE_COLOR));
   wattron(finger_win, A_BOLD);
   box(finger_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(finger_win, 0, 2, "FingerPrint %s", Host_In_LAN[*Pointer].ip);

   mvwprintw(finger_win, 2, 2, "Operating System:");
   mvwprintw(finger_win, dimY-3, 2, "Network Adapter :");

   wattroff(finger_win, A_BOLD);
   wbkgdset(finger_win, COLOR_PAIR(BOTTOM_COLOR));

   if (strcmp(long_os_fingers, ""))
      strlcpy(temp, strtok(long_os_fingers, "\n"), W_MAINX2-4-18);

   mvwprintw(finger_win, 2, 20, "%s", temp);
   for(i=0; i<j-1; i++)
   {
      memset(temp, 0, W_MAINX2);
      strlcpy(temp, strtok(NULL, "\n"), W_MAINX2-4-18);
      mvwprintw(finger_win, 3+i, 20, "%s", temp);
      #ifdef DEBUG
         Debug_msg("Interface_FingerPrint -- [%s]", temp );
      #endif
   }
   mvwprintw(finger_win, dimY-3, 20, "%s", mac_finger);

   wnoutrefresh(finger_win);
   doupdate();

   wgetch(finger_win);

   delwin(finger_win);
   touchwin(main_window);
   wnoutrefresh(main_window);
   doupdate();

   free(long_os_fingers);
   free(mac_finger);

}



void Interface_EntryRemoval(void)
{
#ifdef DEBUG
   Debug_msg("Interface_EntryRemoval -- %d", *Pointer);
#endif

   if (*Pointer == 0 || number_of_hosts_in_lan == 1)
   {
      Interface_PopUp("You cannot remove yourself from the list !!");
      return;
   }

   if (*Pointer < number_of_hosts_in_lan-1)
      memmove(&Host_In_LAN[*Pointer], &Host_In_LAN[*Pointer+1], (number_of_hosts_in_lan-1-*Pointer)*sizeof(HOST));
   else
      *Pointer = *Pointer - 1;

   number_of_hosts_in_lan--;

   Host_In_LAN = realloc(Host_In_LAN, number_of_hosts_in_lan*sizeof(HOST));
   if (Host_In_LAN == NULL)
      Error_msg("ec_interface:%d realloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

}



void Interface_Run(void)
{
   int KeyPress;

#ifdef DEBUG
   Debug_msg("Interface_Run");
#endif

   if (Options.arpsniff)
      Interface_Connect();
   if (Options.macsniff)
      Interface_OldStyleSniff(1);
   if (Options.sniff)
      Interface_OldStyleSniff(0);
   #ifdef PERMIT_PLUGINS
      if (Options.plugin)
         Interface_Plugins_Run();
   #endif

   if (Options.silent && !(Options.sniff || Options.macsniff || Options.arpsniff))
      Options.silent = 0;

   if (Options.passive)
   {
      Interface_Passive_Run();
      Interface_InitList();
   }

   if (Options.hoststofile)
      Interface_PopUp("Host list dumped into file: %s", Inet_Save_Host_List());

   loop
   {
      KeyPress = wgetch(main_window);

      switch (KeyPress)
      {
         case KEY_DOWN:
                  Interface_PointItem(DOWN, 0);
                  break;

         case KEY_UP:
                  Interface_PointItem(UP, 0);
                  break;

         case KEY_LEFT:
                  Interface_PointItem(0, LEFT);
                  break;

         case KEY_RIGHT:
                  Interface_PointItem(0, RIGHT);
                  break;

         case KEY_NPAGE:
                  Interface_PointItem(Sel_Number-1, 0);  //PGDOWN
                  break;

         case KEY_PPAGE:
                  Interface_PointItem(-Sel_Number+1, 0); //PGUP
                  break;

         case KEY_TAB:
                  Interface_KeyTab();
                  Interface_InitList();
                  break;

         case KEY_RETURN:
                  Interface_SelectItem();
                  break;

         case 'A':
         case 'a':
                  Options.arpsniff = 1;
                  Options.sniff = 0;
                  Options.macsniff = 0;
                  Interface_Connect();
                  break;

         case 'S':
         case 's':
                  Options.arpsniff = 0;
                  Options.sniff = 1;
                  Options.macsniff = 0;
                  Interface_OldStyleSniff(0);
                  break;

         case 'M':
         case 'm':
                  Options.arpsniff = 0;
                  Options.sniff = 0;
                  Options.macsniff = 1;
                  Interface_OldStyleSniff(1);
                  break;

         case 'C':
         case 'c':
                  Interface_CheckForPoisoner();
                  break;

         case 'F':
         case 'f':
                  Interface_FingerPrint();
                  break;

         case 'O':
         case 'o':
                  Interface_Passive_Run();
                  Interface_InitList();
                  break;

         case ' ':
                  werase(top_window);
                  wnoutrefresh(top_window);
                  doupdate();
                  memset(&Host_Source, 0, sizeof(HOST));
                  memset(&Host_Dest, 0, sizeof(HOST));
                  break;

         case 'X':
         case 'x':
                  Interface_Factory_Run();
                  Interface_Redraw();
                  break;

         case 'D':
         case 'd':
                  Interface_EntryRemoval();
                  Interface_InitList();
                  break;

#ifdef PERMIT_PLUGINS
         case 'P':
         case 'p':
                  Interface_Plugins_Run();
                  break;
#endif


         case KEY_F(1):
         case 'H':
         case 'h':{
                     static char *help[] = {
                        "[qQ][F10] - quit",
                        "[return]  - select the IP",
                        "[space]   - deselect the IPs",
                        "[tab]     - switch between source and dest",
                        "[aA]      - ARP poisoning based sniffing ",
                        "             . for sniffing on switched LAN",
                        "             . for man-in-the-middle technique",
                        "[sS]      - IP based sniffing",
                        "[mM]      - MAC based sniffing",
                        "[dD]      - delete an entry from the list",
                        "[xX]      - Packet Forge",
#ifdef PERMIT_PLUGINS
                        "[pP]      - run a plugin",
#endif
                        "[fF]      - OS fingerprint",
                        "[oO]      - passive host identification",
                        "[cC]      - check for other poisoner...",
                        "[rR]      - refresh the list",
                        "[kK]      - save host list to a file",
                        "[hH]      - this help screen",
                        NULL};
                     Interface_HelpWindow(help);
                  }
                  Interface_Redraw();
                  break;

         case 'R':
         case 'r':
                  Interface_RefreshList();
                  Interface_Redraw();
                  Interface_InitList();
                  break;

         case 'K':
         case 'k':
                  Interface_PopUp("Host list dumped to file: %s", Inet_Save_Host_List());
                  break;

         case KEY_CTRL_L:  // CTRL+L refresh the screen
                  Interface_Redraw();
                  break;

         case 'q':
         case 'Q':
                  #ifdef DEBUG
                     Debug_msg("Interface_Run_END");
                  #endif
                  {
                     char answer;
                     answer = Interface_PopUp("Do U really want to exit (y/n)?");
                     if ((answer == 'y') || (answer == 'Y'))
                        Interface_WExit("They are safe!!  for now... ");
                  }
                  break;

         case KEY_F(10):
                  #ifdef DEBUG
                     Debug_msg("Interface_Run_END");
                  #endif
                  Interface_WExit("");
                  break;

         default:
                  //beep();
                  #ifdef DEBUG
                     Debug_msg("KeyPress in octal: %o  in decimal: %d", KeyPress, KeyPress);
                  #endif
                  break;
      }
   }

}



void Interface_CloseScreen(void)
{
#ifdef DEBUG
   Debug_msg("Interface_CloseScreen");
#endif

   curs_set(1);
   clear();
   refresh();
   endwin();

#if defined (HAVE_TERMIOS_H) && !defined(CYGWIN)
   tcsetattr(0, TCSANOW, &original_term_info);
#endif

}



void Interface_WExit(char *buffer)
{

#ifdef DEBUG
   Debug_msg("Interface_WExit -- [%s]", buffer);
#endif

   if (ScreenMode) Interface_CloseScreen();

   fprintf(stdout, "\033[01m\033[1m%s %s brought from the dark side of the net by ALoR and NaGA...\033[0m\n\n", PROGRAM, VERSION);
   fprintf(stdout, "\033[01m\033[1mmay the packets be with you...\033[0m\n\n");
   fprintf(stdout, "\n%s\n\n", buffer);

   exit(0);
}


#endif

/* EOF */
