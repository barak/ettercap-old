/*
    ettercap -- ncurses interface for plugins

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

    $Id: ec_interface_plugins.c,v 1.7 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#ifdef PERMIT_PLUGINS
#ifdef HAVE_NCURSES  // don't compile if ncurses interface is not supported

#ifdef HAVE_NCURSES_H
   #include <ncurses.h>
#else
   #include <curses.h>
#endif


#include <ctype.h>

#include "include/ec_interface.h"
#include "include/ec_plugins.h"
#include "include/ec_buffer.h"

#define BOTTOM_COLOR 1
#define TITLE_COLOR  2
#define HELP_COLOR   6
#define NORM_COLOR   6
#define REV_COLOR    7

#define KEY_RETURN   10
#define KEY_CTRL_L   12

#define PAD_BUFFER 500        // buffered lines for plugin window

// protos....

void Interface_Plugins_Run(void);
void Interface_Plugins_Redraw(void);
void Interface_Plugins_Winch(void);
char Interface_Plugins_PopUp(char *question);
void Interface_Plugins_PointItem(char direction);
void Interface_Plugins_InitList(void);
void Interface_Plugins_SelectItem(void);
void Interface_Plugins_Scroll(short direction);
void Interface_Plugins_DrawScroller(void);
void Interface_Plugins_Output(void);
void Interface_Plugins_Output_Scroll(short direction);
void Interface_Plugins_Output_DrawScroller(void);
void Interface_Plugins_PluginOutput(void);
void Interface_Plugins_HidePluginOutput(void);

// global variables

WINDOW *plugin_window, *b_plugin_window;
extern WINDOW *main_window, *top_window, *b_top_window;
WINDOW *output_window, *o_win;

extern int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2, W_SELECTPLUG;
extern int W_BOTTOMY1, W_BOTTOMY2;

extern struct plug_array *Plugins_Array;  // ec_plugins.c

short number_of_plugins;

extern int Sel_Number;
int Plug_Base_Pointer = 0;
int Plug_Pointer = 0;
short P_Sel_Number;

#define LMARGIN 0

short scroll_yp, scroll_out_yp;

// -------------------


void Interface_Plugins_Winch(void)  // TODO better handling...
{
#ifdef DEBUG
   Debug_msg("Interface_Plugin_Winch\tTODO");
#endif

   Interface_Plugins_Redraw();
}


void Interface_Plugins_Redraw(void)
{

   Interface_Redraw();

#ifdef DEBUG
   Debug_msg("Interface_Plugins_Redraw");
#endif

   redrawwin(b_plugin_window);

   wnoutrefresh(b_plugin_window);
   pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);

   doupdate();

}


char Interface_Plugins_PopUp(char *question)
{
   WINDOW *question_window;
   char answer;

   question_window = newwin(5, strlen(question) + 4,0,0);
   mvwin(question_window, W_MAINY1+(W_MAINY2-W_MAINY1)/2-2, W_MAINX2/2 - (strlen(question)+4)/2 );
   wbkgdset(question_window, COLOR_PAIR(TITLE_COLOR));
   wattron(question_window, A_BOLD);
   box(question_window,ACS_VLINE,ACS_HLINE);
   mvwprintw(question_window,  2, 2, "%s", question);
   wnoutrefresh(question_window);
   doupdate();
   answer = wgetch(question_window);
   delwin(question_window);
   touchwin(plugin_window);
   pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);

   doupdate();

#ifdef DEBUG
   Debug_msg("Interface_PLugins_PopUp returns -- %c", answer);
#endif

   return answer;
}



void Interface_Plugins_InitList(void)
{

   int j;
   int Plug_Top_Pointer;

   if (has_colors())
      wbkgdset(plugin_window, COLOR_PAIR(NORM_COLOR));
   else
      wattroff(plugin_window,A_REVERSE);

   werase(plugin_window);

   if (number_of_plugins == 0)      // no plugin... no action... ;)
   {
      wmove(plugin_window, scroll_yp, LMARGIN );
      wprintw(plugin_window, "NO plugin available in %s or in ./ !!\n", PLUGIN_PATH);
      pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
      doupdate();
      return;
   }

   Plug_Top_Pointer = (Plug_Base_Pointer+P_Sel_Number < number_of_plugins) ? Plug_Base_Pointer + P_Sel_Number : number_of_plugins ;

   for(j=Plug_Base_Pointer; j<Plug_Top_Pointer; j++)     // prints connections within the plugin_window height
   {
      wmove(plugin_window, scroll_yp + j - Plug_Base_Pointer, LMARGIN );

      if (Plugins_Array[j].status == 'A')
         wbkgdset(plugin_window, COLOR_PAIR(BOTTOM_COLOR));

      wprintw(plugin_window, "%3d) %-11s  %.1f %c -- %s", j+1, Plugins_Array[j].name,
                                                              Plugins_Array[j].version,
                                                              Plugins_Array[j].status,
                                                              Plugins_Array[j].description);
      wbkgdset(plugin_window, COLOR_PAIR(NORM_COLOR));
   }

   if (has_colors())
      wbkgdset(plugin_window, COLOR_PAIR(REV_COLOR));
   else
      wattron(plugin_window,A_REVERSE);

   wmove(plugin_window, scroll_yp + Plug_Pointer - Plug_Base_Pointer, LMARGIN );
   whline(plugin_window, ' ', W_SELECTPLUG);
   wprintw(plugin_window, "%3d) %-11s  %.1f %c -- %s", Plug_Pointer+1,
                                                      Plugins_Array[Plug_Pointer].name,
                                                      Plugins_Array[Plug_Pointer].version,
                                                      Plugins_Array[Plug_Pointer].status,
                                                      Plugins_Array[Plug_Pointer].description);

   pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
   doupdate();

}



void Interface_Plugins_PointItem(char direction)
{

   int Old_Plug_Pointer;

   if (number_of_plugins == 0) return; // no plugin... no action... ;)

   Old_Plug_Pointer = Plug_Pointer;

   Plug_Pointer += direction;

   if (Plug_Pointer > number_of_plugins -1 ) Plug_Pointer = number_of_plugins - 1;
   if (Plug_Pointer < 0) Plug_Pointer = 0;


   if ( (Plug_Pointer - Plug_Base_Pointer + direction  >= P_Sel_Number) && (direction > 0) )    // scroll down
   {
      if (Plug_Base_Pointer + P_Sel_Number <= number_of_plugins)
         Plug_Base_Pointer = (Plug_Base_Pointer + direction < number_of_plugins) ? Plug_Base_Pointer + direction : number_of_plugins - P_Sel_Number;

      Interface_Plugins_InitList();
   }
   else if ( (Plug_Pointer - Plug_Base_Pointer + direction < 0) && (direction < 0) )         // scroll up
   {
      if (Plug_Base_Pointer > 0)
         Plug_Base_Pointer = (Plug_Base_Pointer + direction > 0) ? Plug_Base_Pointer + direction : 0;

      Interface_Plugins_InitList();
   }


   if (has_colors())
      wbkgdset(plugin_window, COLOR_PAIR(NORM_COLOR));
   else
      wattroff(plugin_window,A_REVERSE);


   if ( (Old_Plug_Pointer >= Plug_Base_Pointer) && (Old_Plug_Pointer <= Plug_Base_Pointer + P_Sel_Number -1))  // DON'T redraw previous selected item if it is out of view
   {
      wmove(plugin_window, scroll_yp + Old_Plug_Pointer - Plug_Base_Pointer, LMARGIN);
      whline(plugin_window,' ', W_SELECTPLUG);                          //deletes the previous position

      if (Plugins_Array[Old_Plug_Pointer].status == 'A')
         wbkgdset(plugin_window, COLOR_PAIR(BOTTOM_COLOR));

      wprintw(plugin_window, "%3d) %-11s  %.1f %c -- %s", Old_Plug_Pointer+1,
                                                         Plugins_Array[Old_Plug_Pointer].name,
                                                         Plugins_Array[Old_Plug_Pointer].version,
                                                         Plugins_Array[Old_Plug_Pointer].status,
                                                         Plugins_Array[Old_Plug_Pointer].description);
      wbkgdset(plugin_window, COLOR_PAIR(NORM_COLOR));
   }

   if (has_colors())
      wbkgdset(plugin_window, COLOR_PAIR(REV_COLOR));
   else
      wattron(plugin_window,A_REVERSE);

   wmove(plugin_window, scroll_yp + Plug_Pointer - Plug_Base_Pointer, LMARGIN);
   whline(plugin_window, ' ', W_SELECTPLUG);                         //select new position
   wprintw(plugin_window, "%3d) %-11s  %.1f %c -- %s", Plug_Pointer+1,
                                                      Plugins_Array[Plug_Pointer].name,
                                                      Plugins_Array[Plug_Pointer].version,
                                                      Plugins_Array[Plug_Pointer].status,
                                                      Plugins_Array[Plug_Pointer].description);


   pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
   doupdate();

}



void Interface_Plugins_DrawScroller(void)
{
   short sheight = (W_MAINY2-10)*(W_MAINY2-10)/PAD_BUFFER;
   short vpos = (W_MAINY2-6)*scroll_yp/PAD_BUFFER;

   sheight = (sheight < 1) ? 1 : sheight;

   vpos = (vpos == 0) ? 1 : vpos;
   vpos = (vpos > W_MAINY2-9-sheight) ? W_MAINY2-9-sheight : vpos;


   mvwvline(b_plugin_window, 1, W_MAINX2 - 4, ACS_VLINE, W_MAINY2-10);

   wattron(b_plugin_window, A_REVERSE);
   mvwvline(b_plugin_window, vpos, W_MAINX2 - 4, ' ', sheight);
   wnoutrefresh(b_plugin_window);
   wattroff(b_plugin_window, A_REVERSE);

}


void Interface_Plugins_Scroll(short direction)
{

   scroll_yp += direction;
   scroll_yp = (scroll_yp < 0) ? 0 : scroll_yp;
   scroll_yp = (scroll_yp > PAD_BUFFER - (W_MAINY2-10)) ? PAD_BUFFER - (W_MAINY2-10) : scroll_yp;

   pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
   Interface_Plugins_DrawScroller();

   doupdate();
}




void Interface_Plugins_SelectItem(void)
{
   int KeyPress;

#ifdef DEBUG
   Debug_msg("Interface_Plugins_SelectItem");
#endif

   if (number_of_plugins == 0) return; // no plugin... no action... ;)

   scroll_yp = PAD_BUFFER - (W_MAINY2-10);

   wbkgdset(plugin_window, COLOR_PAIR(NORM_COLOR));
   werase(plugin_window);
   wmove(plugin_window, scroll_yp, 0);
   pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
   doupdate();

   if (Plugins_Array[Plug_Pointer].status == 'E')
   {
      if (!Plugin_RunExt(Plugins_Array[Plug_Pointer].name))
      {
         Interface_Plugins_PopUp("There was an error loading this plugin !!");
         return;
      }

      loop
      {
         KeyPress = wgetch(plugin_window);

         switch(KeyPress)
         {
               case KEY_DOWN:
                     Interface_Plugins_Scroll( +1 );
                     break;

               case KEY_UP:
                     Interface_Plugins_Scroll( -1 );
                     break;

               case KEY_NPAGE:
                     Interface_Plugins_Scroll( W_MAINY2-10 );     //PGDOWN
                     break;

               case KEY_PPAGE:
                     Interface_Plugins_Scroll( -(W_MAINY2-10) );  //PGUP
                     break;

               case KEY_F(10):
               case 'Q':
               case 'q':
                        scroll_yp = PAD_BUFFER - (W_MAINY2-10);
                        Interface_Plugins_DrawScroller();
                        return;
                        break;
         }
      }
   }
   else  // it is an hooking plugin
   {
      Plugins_Array[Plug_Pointer].status = (Plugins_Array[Plug_Pointer].status == 'A') ? ' ' : 'A';
   }

}


void Interface_Plugins_Output_DrawScroller(void)
{
   short sheight = (W_MAINY2-1)*(W_MAINY2-1)/PAD_BUFFER;
   short vpos = (W_MAINY2+1)*scroll_out_yp/PAD_BUFFER;

   sheight = (sheight < 1) ? 1 : sheight;

   vpos = (vpos == 0) ? 1 : vpos;
   vpos = (vpos > W_MAINY2-sheight) ? W_MAINY2-sheight : vpos;

   mvwvline(o_win, 1, W_MAINX2, ACS_VLINE, W_MAINY2-1);

   wattron(o_win, A_REVERSE);
   mvwvline(o_win, vpos, W_MAINX2, ' ', sheight);
   wnoutrefresh(o_win);
   wattroff(o_win, A_REVERSE);

}

void Interface_Plugins_Output_Scroll(short direction)
{

   scroll_out_yp += direction;
   scroll_out_yp = (scroll_out_yp < 0) ? 0 : scroll_out_yp;
   scroll_out_yp = (scroll_out_yp > PAD_BUFFER - (W_MAINY2-1)) ? PAD_BUFFER - (W_MAINY2-1) : scroll_out_yp;

   pnoutrefresh(output_window, scroll_out_yp, 0, 1, 2, W_MAINY2-1 , W_MAINX2 - 2);
   Interface_Plugins_Output_DrawScroller();

   doupdate();
}


void Interface_Plugins_Output(void)
{
   fd_set msk_fd;
   struct timeval TimeOut;
   short saved_yp = scroll_out_yp;
   int KeyPress;

   memset(&TimeOut, 0, sizeof(TimeOut));  //  timeout = 0
   FD_ZERO(&msk_fd);

   if (o_win != NULL)
   {
      delwin(o_win);
      o_win = NULL;
   }

   if (o_win == NULL)
   {
      o_win = newwin(W_MAINY2+1, W_MAINX2+1, 0, 0);
      wbkgdset(o_win, COLOR_PAIR(HELP_COLOR));
      wattron(o_win, A_BOLD);
      box(o_win,ACS_VLINE,ACS_HLINE);
      mvwprintw(o_win,  0, 2, "Plugin output :");
      keypad(o_win, TRUE);
   }

   if (scroll_out_yp == 0) scroll_out_yp = PAD_BUFFER - 4;
   scroll_out_yp -= (W_MAINY2-4);

   Interface_Plugins_Output_DrawScroller();
   wnoutrefresh(o_win);
   pnoutrefresh(output_window, scroll_out_yp, 0, 1, 2, W_MAINY2-1 , W_MAINX2 - 2);
   doupdate();

   loop
   {
      FD_SET(0, &msk_fd);

      select(FOPEN_MAX, &msk_fd, (fd_set *) 0, (fd_set *) 0, &TimeOut);

      if (FD_ISSET(0, &msk_fd))
      {
         KeyPress = wgetch(o_win);

         switch(KeyPress)
         {
               case KEY_DOWN:
                     Interface_Plugins_Output_Scroll( +1 );
                     break;

               case KEY_UP:
                     Interface_Plugins_Output_Scroll( -1 );
                     break;

               case KEY_NPAGE:
                     Interface_Plugins_Output_Scroll( W_MAINY2 );     //PGDOWN
                     break;

               case KEY_PPAGE:
                     Interface_Plugins_Output_Scroll( -(W_MAINY2) );  //PGUP
                     break;

               case 'D':
               case 'd':
                     {
                        FILE *bin_dump, *str_dump;
                        int ch, ok = 0;

                        bin_dump = tmpfile();
                        putwin(output_window, bin_dump);
                        str_dump = fopen("plugin_output_dump.log", "wb");
                        rewind(bin_dump);
                        fseek(bin_dump, 0x48, SEEK_CUR); // skip the header file
                        while( (ch = fgetc(bin_dump)) != EOF)
                        {
                           if (isprint(ch))
                           {
                              if (!ok && ch != 0x20) ok = 1;
                              if (ok)
                              {
                                 if (ok++ == (W_MAINX2-2))
                                 {
                                    fputc('\n', str_dump);
                                    ok = 1;
                                 }
                                 else
                                    fputc(ch, str_dump);
                              }
                           }
                        }
                        Interface_PopUp("Data dumped to : plugin_output_dump.log");
                        touchwin(o_win);
                        wnoutrefresh(o_win);
                     }
                     break;

               case KEY_F(1):
               case 'H':
               case 'h':{
                           static char *help[] = {
                              "[qQ][F10] - quit",
                              "[arrows]  - scroll the output",
                              "[dD]      - dump plugins output to a file",
                              "[hH]      - this help screen",
                              NULL};
                           Interface_HelpWindow(help);
                        }
                  Interface_Plugins_Redraw();
                  break;

               case KEY_F(10):
               case 'Q':
               case 'q':
                     delwin(o_win);
                     o_win = NULL;
                     scroll_out_yp = saved_yp;
                     return;
                     break;
         }
      }
      else
      {
         Interface_Plugins_PluginOutput();
         pnoutrefresh(output_window, scroll_out_yp, 0, 1, 2, W_MAINY2-1 , W_MAINX2 - 2);
         doupdate();
         usleep(5000);
      }
   }

}


void Interface_Plugins_PluginOutput(void)
{
   int mesglen = 0;
   char message[500];

   Buffer_Get(pipe_with_plugins, &mesglen, sizeof(int));
   Buffer_Get(pipe_with_plugins, message, mesglen);

   message[mesglen] = 0;

   if (!mesglen) return;

   if (o_win == NULL)
   {
      o_win = newwin(5, W_MAINX2+1, 0, 0);
      if (output_window == NULL)
      {
         output_window = newpad(PAD_BUFFER, W_MAINX2 - 2);
         scroll_out_yp = PAD_BUFFER - 4;
         wmove(output_window, scroll_out_yp, 0);
         scrollok(output_window, TRUE);
      }
      wbkgdset(o_win, COLOR_PAIR(HELP_COLOR));
      wattron(o_win, A_BOLD);
      box(o_win,ACS_VLINE,ACS_HLINE);
      mvwprintw(o_win,  0, 2, "Plugin output :");
      wbkgdset(output_window, COLOR_PAIR(BOTTOM_COLOR));
   }

   touchwin(o_win);
   wprintw(output_window, "%s", message);
   wnoutrefresh(o_win);
   pnoutrefresh(output_window, scroll_out_yp, 0, 1, 2, 3 , W_MAINX2 - 2);
   //doupdate();
}



void Interface_Plugins_HidePluginOutput(void)
{
   if (o_win != NULL)
   {
      delwin(o_win);
      o_win = NULL;
      touchwin(top_window);
      touchwin(b_top_window);
      wnoutrefresh(b_top_window);
      wnoutrefresh(top_window);
      doupdate();
   }
}



void Interface_Plugins_Run(void)
{
   int KeyPress, i;

#ifdef DEBUG
   Debug_msg("Interface_Plugins_Run");
#endif

   P_Sel_Number = Sel_Number - 4;

   b_plugin_window = newwin(W_MAINY2 - W_MAINY1 - 3, W_MAINX2 - W_MAINX1 - 3, W_MAINY1 + 2, W_MAINX1 + 2);
   plugin_window = newpad(PAD_BUFFER, W_MAINX2 - 6);

   scroll_yp = PAD_BUFFER - (W_MAINY2-10);

   wmove(plugin_window, scroll_yp, 0);

   init_pair(REV_COLOR, COLOR_BLACK, COLOR_CYAN);

   wbkgdset(plugin_window, COLOR_PAIR(NORM_COLOR));      // sets the colors
   wbkgdset(b_plugin_window, COLOR_PAIR(TITLE_COLOR));

   scrollok(plugin_window, TRUE);

   werase(plugin_window);
   keypad(plugin_window,1);
   wattron(b_plugin_window, A_BOLD);
   box(b_plugin_window,ACS_VLINE,ACS_HLINE);

   wnoutrefresh(b_plugin_window);
   pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
   doupdate();

   if (!Plugins_Array) number_of_plugins = Plugin_ExtArray();

   Interface_Plugins_DrawScroller();
   Interface_Plugins_InitList();

   loop
   {
      KeyPress = wgetch(plugin_window);

      switch (KeyPress)
      {
         case KEY_DOWN:
                  Interface_Plugins_PointItem( +1 );
                  break;

         case KEY_UP:
                  Interface_Plugins_PointItem( -1 );
                  break;

         case KEY_NPAGE:
                  Interface_Plugins_PointItem(P_Sel_Number-1);    //PGDOWN
                  break;

         case KEY_PPAGE:
                  Interface_Plugins_PointItem(-P_Sel_Number+1);   //PGUP
                  break;


         case KEY_RETURN:
                  Interface_Plugins_SelectItem();
                  Interface_Plugins_InitList();
                  break;


         case KEY_F(1):
         case 'H':
         case 'h':{
                     static char *help[] = {
                        "[qQ][F10] - quit",
                        "[return]  - if external: run the selected plug in",
                        "          - if hooking : activate/deactivate it",
                        "[hH]      - this help screen",
                        NULL};
                     Interface_HelpWindow(help);
                  }
                  Interface_Plugins_Redraw();
                  break;


         case KEY_CTRL_L:  // CTRL+L refresh the screen
                  Interface_Plugins_Redraw();
                  break;

         case 'q':
         case 'Q':
         case KEY_F(10):
                  #ifdef DEBUG
                     Debug_msg("Interface_Plugin_Run_END");
                  #endif

                  for(i=0; i< number_of_plugins; i++)    // activate the plugins
                     if (Plugins_Array[i].status == 'A')
                        Plugin_SetActivation(Plugins_Array[i].name, 1);
                     else if (Plugins_Array[i].status == ' ')
                        Plugin_SetActivation(Plugins_Array[i].name, 0);

                  delwin(plugin_window);
                  delwin(b_plugin_window);
                  touchwin(main_window);
                  wnoutrefresh(main_window);
                  doupdate();
                  plugin_window = NULL; // for winch see ec_signal.c
                  return;
                  break;
      }
   }

}

#endif   // HAVE_NCURSES
#endif   // PERMIT_PLUGINS

/* EOF */

