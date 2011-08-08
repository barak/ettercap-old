/*
    ettercap -- ncurses interface for data sniffing-logging

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

    $Id: ec_interface_sniff_data.c,v 1.10 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_NCURSES  // don't compile if ncurses interface is not supported

#ifdef HAVE_NCURSES_H
   #include <ncurses.h>
#else
   #include <curses.h>
#endif

#include <sys/types.h>

#include "include/ec_interface.h"
#include "include/ec_interface_inject.h"
#include "include/ec_interface_plugins.h"
#include "include/ec_decodedata.h"
#include "include/ec_dissector.h"
#include "include/ec_illithid.h"
#include "include/ec_buffer.h"
#include "include/ec_error.h"
#include "include/ec_inet_structures.h"

#define PAD_BUFFER 1000        // buffered lines for sniffing


#define BOTTOM_COLOR 1        // color schemes
#define TITLE_COLOR  2
#define MAIN_COLOR   3
#define POINT_COLOR  4
#define SEL_COLOR    5
#define HELP_COLOR   6
#define SNIFF_COLOR  6

#define KEY_TAB      '\t'     // they aren't defined in ncurses.h :(
#define KEY_RETURN   10
#define KEY_CTRL_L   12

#define ASCII_VIEW   0        // data in the sniffing windows...
#define HEX_VIEW     1
#define TEXT_VIEW    2
#define JOINED_VIEW  3

// protos...

void Interface_Sniff_Data_Run(char *ips, int psource, char *ipd, int pdest, char *macs, char *macd, char proto, char *type, short mode);
void Interface_Sniff_Data_Redraw(void);
void Interface_Sniff_Data_KeyTab(void);
void Interface_Sniff_Data_SniffData(void);
void Interface_Sniff_Data_LogToFile(char proto);
void Interface_Sniff_Data_Winch(void);
void Interface_Sniff_Data_StopCont(void);
void Interface_Sniff_Data_View(short mode);
void Interface_Sniff_Data_Scroll(short direction);
void Interface_Sniff_Data_DrawScroller(void);
void Interface_Sniff_Data_Inject(char proto, char *app);
void Interface_Sniff_Data_Kill(char proto);

// global variables

extern WINDOW *main_window, *bottom_window, *top_window;
WINDOW *data_source_win, *data_dest_win, *data_source, *data_dest;
WINDOW *win_pointer;
WINDOW *data_joined_win, *data_joined;


extern int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2;
extern int W_BOTTOMY2;

extern int Conn_Pointer;

short log_source, log_dest, log_joined;
short view;
short stop = 0;
short inject = 0;
short joined = 0;

int inject_tod=0, inject_tos=0;

short scroll_yd = 0, scroll_ys = 0, scroll_yj = 0;

FILE *file_source, *file_dest, *file_joined;

char ipsource[16];
char ipdest[16];
u_short portsource;
u_short portdest;

//---------------------------

void Interface_Sniff_Data_Winch(void)  // TODO better handling...
{
#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_Winch\tTODO");
#endif

   Interface_Sniff_Data_Redraw();
}


void Interface_Sniff_Data_Redraw(void)
{

   Interface_Redraw();

#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_Redraw");
#endif

   if (joined)
   {
      redrawwin(data_joined_win);

      wnoutrefresh(data_joined_win);
      pnoutrefresh(data_joined, scroll_yj, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 4);
   }
   else
   {
      redrawwin(data_dest_win);
      redrawwin(data_source_win);

      wnoutrefresh(data_dest_win);
      wnoutrefresh(data_source_win);
      pnoutrefresh(data_source, scroll_ys, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
      pnoutrefresh(data_dest, scroll_yd, 0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);
   }

   doupdate();
}



void Interface_Sniff_Data_KeyTab(void)
{

   if (joined) return;     // TAB isnt necessary in joined view

   win_pointer = (win_pointer == data_source_win) ? data_dest_win : data_source_win;

   wattroff(data_source_win, A_BOLD);
   wattroff(data_dest_win, A_BOLD);

   wattron(win_pointer, A_BOLD);

   box(data_source_win,ACS_VLINE,ACS_HLINE);
   box(data_dest_win,ACS_VLINE,ACS_HLINE);

   mvwprintw(data_source_win, 0, 1, "%s:%d", ipsource, portsource);
   mvwprintw(data_dest_win, 0, 1, "%s:%d", ipdest, portdest);

   Interface_Sniff_Data_DrawScroller();

   if (log_source) mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, W_MAINX2 / 2 - 10, "LOGGED");
   if (log_dest) mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, W_MAINX2 / 2 - 10, "LOGGED");

   switch(view)
   {
      case ASCII_VIEW:
                        mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2, "ASCII");
                        mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2, "ASCII");
                        break;
      case HEX_VIEW:
                        mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2, "HEX");
                        mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2, "HEX");
                        break;

       case TEXT_VIEW:
                        mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2, "TEXT");
                        mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2, "TEXT");
                        break;
   }

   if (stop) mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2, "STOPPED");
   if (stop) mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2, "STOPPED");

   mvwprintw(win_pointer, 0, W_MAINX2 / 2 - 10, "active");

   redrawwin(data_dest_win);
   redrawwin(data_source_win);

   wnoutrefresh(data_dest_win);
   wnoutrefresh(data_source_win);
   pnoutrefresh(data_source, scroll_ys,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
   pnoutrefresh(data_dest, scroll_yd,0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);

   doupdate();

}




void Interface_Sniff_Data_LogToFile(char proto)
{
   WINDOW *question_window;
   char question[100];
   char filename[60];
   char answer;
   time_t tt;
   struct tm *dd;
   char date[8];

#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_LogToFile");
#endif

   tt = time(NULL);
   dd = localtime(&tt);

   snprintf(date, sizeof(date), "%04d%02d%02d", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday);

   if (joined)
   {
      strcpy(question, "Do U want to log the trafic to this file ? (y/n)");
      snprintf(filename, sizeof(filename), "%s-%c-%s:%d-%s:%d-FULL.log", date, proto, ipsource, portsource, ipdest, portdest);
   }
   else
   {
      if (win_pointer == data_source_win)
      {
         strcpy(question, "Do U want to log SOURCE-to-DEST to this file ? (y/n)");
         snprintf(filename, sizeof(filename), "%s-%c-%s:%d-%s:%d.log", date, proto, ipsource, portsource, ipdest, portdest);
      }
      else
      {
         strcpy(question, "Do U want to log DEST-to-SOURCE to this file ? (y/n)");
         snprintf(filename, sizeof(filename), "%s-%c-%s:%d-%s:%d.log", date, proto, ipdest, portdest, ipsource, portsource);
      }
   }

   question_window = newwin(7, strlen(question) + 8,0,0);
   mvwin(question_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(question)+8)/2 );
   wbkgdset(question_window, COLOR_PAIR(TITLE_COLOR));
   wattron(question_window, A_BOLD);
   box(question_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(question_window,  2, 4, "%s", question);
   wnoutrefresh(question_window);
   doupdate();

   wbkgdset(question_window, COLOR_PAIR(HELP_COLOR));
   if (joined) mvwprintw(question_window,  4, 2, "%s", filename);
   else mvwprintw(question_window,  4, 6, "%s", filename);
   answer = wgetch(question_window);
   delwin(question_window);

   if ( (answer == 'y') || (answer == 'Y') )
   {
      if (joined)
      {
         file_joined = fopen(filename, "a");
         if (file_joined == NULL)
            ERROR_MSG("fopen()");
         log_joined = 1;
         mvwprintw(data_joined_win, W_MAINY2 - W_MAINY1 - 4, W_MAINX2 - 15, "LOGGED");
      }
      else
      {
         if (win_pointer == data_source_win)
         {
            file_source = fopen(filename, "a");
            if (file_source == NULL)
               ERROR_MSG("fopen()");
            log_source = 1;
            mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, W_MAINX2 / 2 - 10, "LOGGED");
         }
         else
         {
            file_dest = fopen(filename, "a");
            if (file_dest == NULL)
               ERROR_MSG("fopen()");
            log_dest = 1;
            mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, W_MAINX2 / 2 - 10, "LOGGED");
         }
      }
   }
   else
   {
      if (joined)
      {
         if (log_joined) fclose(file_joined);
         log_joined = 0;
         wmove(data_joined_win, W_MAINY2 - W_MAINY1 - 4, W_MAINX2 - 15);
         whline(data_joined_win, ACS_HLINE, 6);
      }
      else
      {
         if (win_pointer == data_source_win)
         {
            if (log_source) fclose(file_source);
            log_source = 0;
            wmove(data_source_win, W_MAINY2 - W_MAINY1 - 4, W_MAINX2 / 2 - 10);
            whline(data_source_win, ACS_HLINE, 6);
         }
         else
         {
            if (log_dest) fclose(file_dest);
            log_dest = 0;
            wmove(data_dest_win, W_MAINY2 - W_MAINY1 - 4, W_MAINX2 / 2 - 10);
            whline(data_dest_win, ACS_HLINE, 6);
         }
      }
   }


#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_LogToFile returns -- %c", answer);
   if ( (answer == 'y') || (answer == 'Y') ) Debug_msg("\t %s", filename);
#endif

   Interface_Sniff_Data_Redraw();

}


void Interface_Sniff_Data_StopCont(void)
{
#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_StopCont");
#endif


   if (stop == 0)
   {
      if (joined)
      {
         mvwprintw(data_joined_win, W_MAINY2 - W_MAINY1 - 4, 2, "STOPPED");
      }
      else
      {
         mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2, "STOPPED");
         mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2, "STOPPED");
      }
      stop = 1;
   }
   else
   {
      if (joined)
      {
         wmove(data_joined_win, W_MAINY2 - W_MAINY1 - 4, 2);   whline(data_joined_win, ACS_HLINE, 7);
      }
      else
      {
         wmove(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2);   whline(data_source_win, ACS_HLINE, 7);
         wmove(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2); whline(data_dest_win, ACS_HLINE, 7);
      }

      Interface_Sniff_Data_View(view);
      stop = 0;
   }


   if (joined)
   {
      redrawwin(data_joined_win);

      wnoutrefresh(data_joined_win);
      pnoutrefresh(data_joined, scroll_yj, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 4);
   }
   else
   {
      redrawwin(data_dest_win);
      redrawwin(data_source_win);

      wnoutrefresh(data_dest_win);
      wnoutrefresh(data_source_win);
      pnoutrefresh(data_source, scroll_ys, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
      pnoutrefresh(data_dest, scroll_yd, 0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);
   }

   doupdate();

}



void Interface_Sniff_Data_View(short mode)
{
#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_View -- %d", mode);
#endif


   switch(mode)
   {
      case ASCII_VIEW:
                        if (joined)
                        {
                           wmove(data_joined_win, W_MAINY2 - W_MAINY1 - 4, 2);   whline(data_joined_win, ACS_HLINE, 7);
                           mvwprintw(data_joined_win, W_MAINY2 - W_MAINY1 - 4, 2, "ASCII");
                        }
                        else
                        {
                           wmove(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2);   whline(data_source_win, ACS_HLINE, 7);
                           wmove(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2); whline(data_dest_win, ACS_HLINE, 7);
                           mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2, "ASCII");
                           mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2, "ASCII");
                        }
                        break;

      case HEX_VIEW:
                        if (joined)
                        {
                           wmove(data_joined_win, W_MAINY2 - W_MAINY1 - 4, 2);   whline(data_joined_win, ACS_HLINE, 7);
                           mvwprintw(data_joined_win, W_MAINY2 - W_MAINY1 - 4, 2, "HEX");
                        }
                        else
                        {
                           wmove(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2);   whline(data_source_win, ACS_HLINE, 7);
                           wmove(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2); whline(data_dest_win, ACS_HLINE, 7);
                           mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2, "HEX");
                           mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2, "HEX");
                        }
                        break;

      case TEXT_VIEW:
                        if (joined)
                        {
                           wmove(data_joined_win, W_MAINY2 - W_MAINY1 - 4, 2);   whline(data_joined_win, ACS_HLINE, 7);
                           mvwprintw(data_joined_win, W_MAINY2 - W_MAINY1 - 4, 2, "TEXT");
                        }
                        else
                        {
                           wmove(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2);   whline(data_source_win, ACS_HLINE, 7);
                           wmove(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2); whline(data_dest_win, ACS_HLINE, 7);
                           mvwprintw(data_source_win, W_MAINY2 - W_MAINY1 - 4, 2, "TEXT");
                           mvwprintw(data_dest_win, W_MAINY2 - W_MAINY1 - 4, 2, "TEXT");
                        }
                        break;

      case JOINED_VIEW:
                        if (joined)
                        {
                           joined = 0;
                           delwin(data_joined_win);
                           delwin(data_joined);

                           redrawwin(main_window);
                           redrawwin(data_dest_win);
                           redrawwin(data_source_win);

                           wnoutrefresh(main_window);
                           wnoutrefresh(data_dest_win);
                           wnoutrefresh(data_source_win);

                           pnoutrefresh(data_source, scroll_ys,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
                           pnoutrefresh(data_dest, scroll_yd,0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);

                           doupdate();
                        }
                        else
                        {
                           joined = 1;

                           data_joined_win = newwin(W_MAINY2 - W_MAINY1 - 3, W_MAINX2 - 4, W_MAINY1 + 2, 2);
                           data_joined = newpad(PAD_BUFFER, W_MAINX2 - 6);

                           wbkgdset(data_joined_win, COLOR_PAIR(SNIFF_COLOR));
                           wattron(data_joined_win, A_BOLD);
                           box(data_joined_win, ACS_VLINE, ACS_HLINE);
                           mvwprintw(data_joined_win, 0, 1, "%s:%d - %s:%d", ipsource, portsource, ipdest, portdest);
                           scroll_yj = PAD_BUFFER - (W_MAINY2-10);
                           mvwprintw(data_joined_win, 0, W_MAINX2 - 15, "JOINED");
                           scrollok(data_joined_win, TRUE);
                           wmove(data_joined, scroll_yj, 0);

                           wnoutrefresh(data_joined_win);
                           pnoutrefresh(data_joined, scroll_yj, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 4);
                           doupdate();

                           Interface_Sniff_Data_DrawScroller();
                           Interface_Sniff_Data_View(ASCII_VIEW);

                        }

                        return;
                        break;
   }

   view = mode;

   if (joined)
   {
      redrawwin(data_joined_win);

      wnoutrefresh(data_joined_win);
      pnoutrefresh(data_joined, scroll_yj, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 4);
   }
   else
   {
      redrawwin(data_dest_win);
      redrawwin(data_source_win);

      wnoutrefresh(data_dest_win);
      wnoutrefresh(data_source_win);
      pnoutrefresh(data_source, scroll_ys, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
      pnoutrefresh(data_dest, scroll_yd, 0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);
   }

   doupdate();

}



void Interface_Sniff_Data_SniffData(void)
{
   SNIFFED_DATA data_from_illithid;
   int datalen;

   datalen = Buffer_Get(pipe_with_illithid_data, &data_from_illithid, sizeof(SNIFFED_DATA));

   if (datalen<=0)
   {
       usleep(1);
       return;
   }

   if (joined)
   {
      if (log_joined) { write(fileno(file_joined), &data_from_illithid.data, data_from_illithid.datasize); fflush(file_joined);}
      if (!stop)
      {
         if ( current_illithid_data.source_ip == data_from_illithid.fast_source_ip)
            wbkgdset(data_joined, COLOR_PAIR(TITLE_COLOR));
         else
            wbkgdset(data_joined, COLOR_PAIR(BOTTOM_COLOR));

         switch (view)
         {
            case ASCII_VIEW:
                           wprintw(data_joined, "%s", Decodedata_GetAsciiData(data_from_illithid.data, data_from_illithid.datasize));
                           pnoutrefresh(data_joined, scroll_yj,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 4);
                           break;

            case TEXT_VIEW:
                           wprintw(data_joined, "%s", Decodedata_GetTextData(data_from_illithid.data, data_from_illithid.datasize));
                           pnoutrefresh(data_joined, scroll_yj,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 4);
                           break;

            case HEX_VIEW:
                           if (data_from_illithid.proto == 'T')
                              wprintw(data_joined, "\n> S %lx A %lx (%s) <\n%s",
                                                data_from_illithid.seq,
                                                data_from_illithid.ack_seq,
                                                Decodedata_TCPFlags(data_from_illithid.flags),
                                                Decodedata_GetHexData(data_from_illithid.data, data_from_illithid.datasize, W_MAINX2/2 - 4));
                           else
                              wprintw(data_joined, "%s", Decodedata_GetHexData(data_from_illithid.data, data_from_illithid.datasize, W_MAINX2/2 - 4));

                           pnoutrefresh(data_joined, scroll_yj,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 4);
                           break;
         }
      }
   }
   else if ( current_illithid_data.source_ip == data_from_illithid.fast_source_ip)
   {
      if (log_source) { write(fileno(file_source), &data_from_illithid.data, data_from_illithid.datasize); fflush(file_source);}
      if (!stop)
         switch (view)
         {
            case ASCII_VIEW:
                           wprintw(data_source, "%s", Decodedata_GetAsciiData(data_from_illithid.data, data_from_illithid.datasize));
                           pnoutrefresh(data_source, scroll_ys,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
                           break;

            case TEXT_VIEW:
                           wprintw(data_source, "%s", Decodedata_GetTextData(data_from_illithid.data, data_from_illithid.datasize));
                           pnoutrefresh(data_source, scroll_ys,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
                           break;

            case HEX_VIEW:
                           if (data_from_illithid.proto == 'T')
                              wprintw(data_source, "\n> S %lx A %lx (%s) <\n%s",
                                                data_from_illithid.seq,
                                                data_from_illithid.ack_seq,
                                                Decodedata_TCPFlags(data_from_illithid.flags),
                                                Decodedata_GetHexData(data_from_illithid.data, data_from_illithid.datasize, W_MAINX2/2 - 4));
                           else
                              wprintw(data_source, "%s", Decodedata_GetHexData(data_from_illithid.data, data_from_illithid.datasize, W_MAINX2/2 - 4));

                           pnoutrefresh(data_source, scroll_ys,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
                           break;
         }
   }
   else
   {
      if (log_dest) { write(fileno(file_dest), &data_from_illithid.data, data_from_illithid.datasize); fflush(file_dest);}
      if (!stop)
         switch (view)
         {
            case ASCII_VIEW:
                           wprintw(data_dest, "%s", Decodedata_GetAsciiData(data_from_illithid.data, data_from_illithid.datasize));
                           pnoutrefresh(data_dest, scroll_yd,0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);
                           break;

            case TEXT_VIEW:
                           wprintw(data_dest, "%s", Decodedata_GetTextData(data_from_illithid.data, data_from_illithid.datasize));
                           pnoutrefresh(data_dest, scroll_yd,0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);
                           break;

            case HEX_VIEW:
                           if (data_from_illithid.proto == 'T')
                              wprintw(data_dest, "\n> S %lx A %lx (%s) <\n%s",
                                                data_from_illithid.seq,
                                                data_from_illithid.ack_seq,
                                                Decodedata_TCPFlags(data_from_illithid.flags),
                                                Decodedata_GetHexData(data_from_illithid.data, data_from_illithid.datasize, W_MAINX2/2 - 4));
                           else
                              wprintw(data_dest, "%s", Decodedata_GetHexData(data_from_illithid.data, data_from_illithid.datasize, W_MAINX2/2 - 4));

                           pnoutrefresh(data_dest, scroll_yd,0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);
                           break;
         }
   }

   doupdate();
}


void Interface_Sniff_Data_DrawScroller(void)
{
   short sheight = (W_MAINY2-10)*(W_MAINY2-10)/PAD_BUFFER;
   short svpos = (W_MAINY2-6)*scroll_ys/PAD_BUFFER;
   short dvpos = (W_MAINY2-6)*scroll_yd/PAD_BUFFER;
   short jvpos = (W_MAINY2-6)*scroll_yj/PAD_BUFFER;

   sheight = (sheight < 1) ? 1 : sheight;

   svpos = (svpos == 0) ? 1 : svpos;
   svpos = (svpos > W_MAINY2-9-sheight) ? W_MAINY2-9-sheight : svpos;

   dvpos = (dvpos == 0) ? 1 : dvpos;
   dvpos = (dvpos > W_MAINY2-9-sheight) ? W_MAINY2-9-sheight : dvpos;

   jvpos = (jvpos == 0) ? 1 : jvpos;
   jvpos = (jvpos > W_MAINY2-9-sheight) ? W_MAINY2-9-sheight : jvpos;

   wattron(win_pointer, A_BOLD);

   if (joined)
   {
      mvwvline(data_joined_win, 1, W_MAINX2 - 5, ACS_VLINE, W_MAINY2-10);
      wattron(data_joined_win, A_REVERSE);
      mvwvline(data_joined_win, jvpos, W_MAINX2 - 5, ' ', sheight);
      wnoutrefresh(data_joined_win);
      wattroff(data_joined_win, A_REVERSE);
   }
   else
   {
      mvwvline(data_source_win, 1, W_MAINX2 / 2 - 3, ACS_VLINE, W_MAINY2-10);
      wattron(data_source_win, A_REVERSE);
      mvwvline(data_source_win, svpos, W_MAINX2 / 2 - 3, ' ', sheight);
      wnoutrefresh(data_source_win);
      wattroff(data_source_win, A_REVERSE);

      mvwvline(data_dest_win, 1, W_MAINX2 / 2 - 3, ACS_VLINE, W_MAINY2-10);
      wattron(data_dest_win, A_REVERSE);
      mvwvline(data_dest_win, dvpos, W_MAINX2 / 2 - 3, ' ', sheight);
      wnoutrefresh(data_dest_win);
      wattroff(data_dest_win, A_REVERSE);
   }

}


void Interface_Sniff_Data_Scroll(short direction)
{

   if (joined)
   {
      scroll_yj += direction;
      scroll_yj = (scroll_yj < 0) ? 0 : scroll_yj;
      scroll_yj = (scroll_yj > PAD_BUFFER - (W_MAINY2-10)) ? PAD_BUFFER - (W_MAINY2-10) : scroll_yj;
      pnoutrefresh(data_joined, scroll_yj, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 4);
      Interface_Sniff_Data_DrawScroller();
   }
   else
   {

      if (win_pointer == data_source_win)
      {
         scroll_ys += direction;
         scroll_ys = (scroll_ys < 0) ? 0 : scroll_ys;
         scroll_ys = (scroll_ys > PAD_BUFFER - (W_MAINY2-10)) ? PAD_BUFFER - (W_MAINY2-10) : scroll_ys;
         pnoutrefresh(data_source, scroll_ys,0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 / 2 - 2);
         Interface_Sniff_Data_DrawScroller();
      }
      else
      {
         scroll_yd += direction;
         scroll_yd = (scroll_yd < 0) ? 0 : scroll_yd;
         scroll_yd = (scroll_yd > PAD_BUFFER - (W_MAINY2-10)) ? PAD_BUFFER - (W_MAINY2-10) : scroll_yd;
         pnoutrefresh(data_dest, scroll_yd,0, W_MAINY1 + 3, W_MAINX2 / 2 + 2, W_MAINY2 - 3 , W_MAINX2 - 2);
         Interface_Sniff_Data_DrawScroller();
      }
   }

   doupdate();
}



void Interface_Sniff_Data_Inject(char proto, char *app)
{

   INJECTED_DATA inject_data;
   int data_len;

#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_Inject");
#endif

   if (joined)
   {
      Interface_PopUp("Injection not possible while in JOINED view");
      Interface_Sniff_Data_Redraw();
      return;
   }

   memset(&inject_data, 0, sizeof(INJECTED_DATA));

   data_len = Interface_Inject_Run(inject_data.data, proto, app);
   Interface_Sniff_Data_Redraw();

   inject_data.proto = proto;
   inject_data.datalen = data_len;

   if (data_len)
   {
      inject = 1;  // on exit the connection must be RSTted

      if (win_pointer == data_dest_win)
      {
         #ifdef DEBUG
            Debug_msg("Interface_Sniff_Data_Inject -- INJECT -- %s", ipdest);
         #endif
         inject_data.source_ip = inet_addr(ipsource);
         inject_data.dest_ip = inet_addr(ipdest);
         inject_data.source_port = htons(portsource);
         inject_data.dest_port = htons(portdest);
         write(pipe_inject[1], &inject_data, sizeof(INJECTED_DATA));
         wmove(bottom_window, 1, 30);
         wbkgdset(bottom_window, COLOR_PAIR(BOTTOM_COLOR));
         wprintw(bottom_window, "%d ", inject_tos += data_len);
         wbkgdset(bottom_window, COLOR_PAIR(SNIFF_COLOR));
         wprintw(bottom_window, "chars injected to %s", ipsource);
      }
      else
      {
         #ifdef DEBUG
            Debug_msg("Interface_Sniff_Data_Inject -- INJECT -- %s", ipsource);
         #endif
         inject_data.source_ip = inet_addr(ipdest);
         inject_data.dest_ip = inet_addr(ipsource);
         inject_data.source_port = htons(portdest);
         inject_data.dest_port = htons(portsource);
         write(pipe_inject[1], &inject_data, sizeof(INJECTED_DATA));
         wmove(bottom_window, 0, 30);
         wbkgdset(bottom_window, COLOR_PAIR(BOTTOM_COLOR));
         wprintw(bottom_window, "%d ", inject_tod += data_len);
         wbkgdset(bottom_window, COLOR_PAIR(SNIFF_COLOR));
         wprintw(bottom_window, "chars injected to %s", ipdest);
      }
   }

   wnoutrefresh(bottom_window);

   doupdate();

}




void Interface_Sniff_Data_Kill(char proto)
{
   KILL_DATA kill_data;

   if (proto == 'U')
   {
      Interface_PopUp("Trying to kill an UDP connection ?!? Ehi Kiddie, go home !!");
      return;
   }

#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_Kill -- %s:%d -> %s:%d ", ipsource, portsource, ipdest, portdest);
#endif

   kill_data.source_ip = inet_addr(ipsource);
   kill_data.dest_ip = inet_addr(ipdest);
   kill_data.source_port = htons(portsource);
   kill_data.dest_port = htons(portdest);
   write(pipe_kill[1], &kill_data, sizeof(KILL_DATA));

   strcpy(Conn_Between_Hosts[Conn_Pointer].status, "KILLED");

   Interface_PopUp("Connection KILLED !!");

}




void Interface_Sniff_Data_Run(char *ips, int psource, char *ipd, int pdest, char *macs, char *macd, char proto, char *type, short mode)
{
   int KeyPress;
   int dimY = W_MAINY2 - W_MAINY1 - 3;
   int dimX = W_MAINX2 / 2 - 2;
   fd_set msk_fd;
   struct timeval TimeOut;
   struct in_addr addr;
   char macsource[20];
   char macdest[20];
   char app[18];

   strlcpy(ipsource, ips, sizeof(ipsource));     // save locally because other threads can
   strlcpy(ipdest, ipd, sizeof(ipdest));         // realloc the array containing these values
   portsource = psource;
   portdest = pdest;

   strlcpy(macsource, macs, sizeof(macsource));
   strlcpy(macdest, macd, sizeof(macdest));
   strlcpy(app, type, sizeof(app));

#ifdef DEBUG
   Debug_msg("Interface_Sniff_Data_Run -- %d -- %c [%s:%d] [%s:%d] [%s] [%s]", mode, proto, ipsource, portsource, ipdest, portdest, macsource, macdest );
#endif

   data_source_win = newwin(dimY, dimX, W_MAINY1 + 2, 2);
   data_dest_win = newwin(dimY, dimX, W_MAINY1 + 2, W_MAINX2 / 2 + 1);
   data_source = newpad(PAD_BUFFER, dimX - 2);
   data_dest = newpad(PAD_BUFFER, dimX - 2);

   win_pointer = data_source_win;

   wbkgdset(data_source_win, COLOR_PAIR(SNIFF_COLOR));
   wbkgdset(data_dest_win, COLOR_PAIR(SNIFF_COLOR));
   wattron(data_source_win, A_BOLD);

   box(data_source_win,ACS_VLINE,ACS_HLINE);
   box(data_dest_win,ACS_VLINE,ACS_HLINE);

   mvwprintw(data_source_win, 0, 1, "%s:%d", ipsource, portsource);
   mvwprintw(data_dest_win, 0, 1, "%s:%d", ipdest, portdest);

   mvwprintw(data_source_win, 0, W_MAINX2 / 2 - 10, "active");

   scrollok(data_source, TRUE);
   scrollok(data_dest, TRUE);

   scroll_yd = PAD_BUFFER - (W_MAINY2-10);
   scroll_ys = PAD_BUFFER - (W_MAINY2-10);

   wmove(data_source, scroll_ys, 0);
   wmove(data_dest, scroll_yd, 0);

   wbkgdset(main_window, COLOR_PAIR(MAIN_COLOR));

   Interface_Sniff_Data_DrawScroller();

   werase(main_window);
   werase(bottom_window);

   wmove(bottom_window, 0, 1);
   wbkgdset(bottom_window, COLOR_PAIR(SNIFF_COLOR));
   wprintw(bottom_window, "Protocol: ");
   wbkgdset(bottom_window, COLOR_PAIR(BOTTOM_COLOR));
   if (proto == 'T')
      wprintw(bottom_window, "TCP");
   else
      wprintw(bottom_window, "UDP");
   wmove(bottom_window, 1, 1);
   wbkgdset(bottom_window, COLOR_PAIR(SNIFF_COLOR));
   wprintw(bottom_window, "Application: ");
   wbkgdset(bottom_window, COLOR_PAIR(BOTTOM_COLOR));
   wprintw(bottom_window, "%s", app);

   redrawwin(main_window);
   wnoutrefresh(main_window);
   wnoutrefresh(bottom_window);

   wnoutrefresh(data_source_win);
   wnoutrefresh(data_dest_win);
   doupdate();

   if (Options.hexview)
   {
      view = HEX_VIEW;
      Options.hexview = 0;
   }

   Interface_Sniff_Data_View(view);    // default view


   memset(&TimeOut, 0, sizeof(TimeOut));  //  timeout = 0
   FD_ZERO(&msk_fd);

   current_illithid_data.proto = proto;
   current_illithid_data.source_port = portsource;
   current_illithid_data.dest_port = portdest;

   if (inet_aton(ipsource, &addr))
      current_illithid_data.source_ip = ntohl(addr.s_addr);
   if (inet_aton(ipdest, &addr))
      current_illithid_data.dest_ip =  ntohl(addr.s_addr);

   Buffer_Flush(pipe_with_illithid_data);

   loop
   {

      FD_SET(0, &msk_fd);

      select(FOPEN_MAX, &msk_fd, (fd_set *) 0, (fd_set *) 0, &TimeOut);

      Interface_Sniff_Data_SniffData();

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
                  Interface_Sniff_Data_Scroll( +1 );
                  break;

            case KEY_UP:
                  Interface_Sniff_Data_Scroll( -1 );
                  break;

            case KEY_NPAGE:
                  Interface_Sniff_Data_Scroll( W_MAINY2-10 );     //PGDOWN
                  break;

            case KEY_PPAGE:
                  Interface_Sniff_Data_Scroll( -(W_MAINY2-10) );  //PGUP
                  break;

            case 'L':
            case 'l':
                  Interface_Sniff_Data_LogToFile(proto);
                  break;

            case 'A':
            case 'a':
                  Interface_Sniff_Data_View(ASCII_VIEW);
                  break;

            case 'X':
            case 'x':
                  Interface_Sniff_Data_View(HEX_VIEW);
                  break;

            case 'T':
            case 't':
                  Interface_Sniff_Data_View(TEXT_VIEW);
                  break;

            case 'J':
            case 'j':
                  Interface_Sniff_Data_View(JOINED_VIEW);
                  break;

            case 'S':
            case 's':
                  Interface_Sniff_Data_StopCont();
                  break;

            case 'I':
            case 'i':
                  if ( mode == ARPBASED )
                  {
                     if (strstr(app, "ssh") || strstr(app, "SSH") || strstr(app, "HTTPS"))
                     {
                        Interface_PopUp("You CAN'T inject in a crypted connection !!");
                        Interface_Sniff_Data_Redraw();
                     }
                     else
                        Interface_Sniff_Data_Inject(proto, app);
                  }
                  else
                  {
                     Interface_PopUp("Characters injection is only supported in ARP Based mode !!");
                     Interface_Sniff_Data_Redraw();
                  }
                  break;

            case 'F':
            case 'f':
                  Interface_Inject_SetFilter(mode);
                  Interface_Sniff_Data_Redraw();
                  break;

            case 'K':
            case 'k':
                  Interface_Sniff_Data_Kill(proto);
                  Interface_Sniff_Data_Redraw();
                  break;

            case KEY_TAB:
                  Interface_Sniff_Data_KeyTab();
                  break;

            case KEY_CTRL_L:  // CTRL+L refresh the screen
                  Interface_Sniff_Data_Redraw();
                  break;

#ifdef PERMIT_PLUGINS
            case 'P':
            case 'p':
                     Interface_Plugins_Run();
                     Interface_Sniff_Data_Redraw();
                     break;
#endif

            case KEY_F(1):
            case 'H':
            case 'h':{
                        static char *help[] = {
                        "[qQ][F10] - quit (and stop sniffing)",
                        "[tab]     - switch between window",
                        "[pgUp]    - scroll back (as well as UpArrow)",
                        "[pgDw]    - scroll forward (as well as DownArrow)",
                        "[iI]      - inject characters in the connection",
                        "[fF]      - set/edit filters chains",
#ifdef PERMIT_PLUGINS
                        "[pP]      - run a plugin",
#endif
                        "[kK]      - kill the connection (be careful !)",
                        "[aA]      - ASCII view",
                        "[xX]      - HEX view",
                        "[tT]      - TEXT (readable chars) only view",
                        "[jJ]      - join the two windows",
                        "[sS]      - stop/cont the sniff (only visualization)",
                        "[lL]      - Log to file",
                        NULL};
                        Interface_HelpWindow(help);
                     }
                     Interface_Sniff_Data_Redraw();
                  break;

            case KEY_F(10):
            case 'Q':
            case 'q':
                     if (log_dest) fclose(file_dest);
                     if (log_source) fclose(file_source);
                     if (log_joined) fclose(file_joined);
                     log_dest = log_source = log_joined = 0;
                     stop = 0;
                     inject_tod=0; inject_tos=0;  // reset counter
                     delwin(data_source_win);
                     data_source_win = NULL;    // for winching (see ec_signal.c)
                     wbkgdset(bottom_window, COLOR_PAIR(BOTTOM_COLOR));
                     mvwhline(top_window, 2, 55, ' ', 20);
                     if (joined)
                     {
                        delwin(data_joined_win);
                        delwin(data_joined);
                        joined = 0;
                     }
                     delwin(data_dest_win);
                     delwin(data_source);
                     delwin(data_dest);
                     werase(bottom_window);
                     wnoutrefresh(top_window);
                     wnoutrefresh(bottom_window);
                     wnoutrefresh(main_window);
                     doupdate();
                     #ifdef DEBUG
                        Debug_msg("Interface_Sniff_Data_End");
                     #endif
                     return;
                  break;
         }
      }

   }

}



#endif

/* EOF */
