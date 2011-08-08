/*
    ettercap -- ncurses interface for data injector and filtering form

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

    $Id: ec_interface_inject.c,v 1.7 2001/12/09 20:24:51 alor Exp $
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
#include "include/ec_interface_sniff_data.h"
#include "include/ec_decodedata.h"
#include "include/ec_error.h"
#include "include/ec_filterdrop.h"
#include "include/ec_parser.h"
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

#define KEY_RETURN   10       // they aren't defined in ncurses.h :(
#define KEY_CTRL_L   12

// protos...


void Interface_Inject_Redraw(void);
void Interface_Inject_SetFilter_Redraw(void);
void Interface_Inject_FilterTopStatus(void);
void Interface_Inject_FilterStatus(void);
int Interface_Inject_Run(u_char *inject_data, char proto, char *app);
int Interface_Inject_Filter(DROP_FILTER *filters);
void Interface_Inject_SetFilter(short mode);
void Interface_Inject_FilterStatus();
void Interface_Inject_EditFilters(DROP_FILTER *FA_ptr);
void Interface_Inject_EditFilters_InitList(DROP_FILTER *FA_ptr);
void Interface_Inject_EditFilters_PointItem(DROP_FILTER *FA_ptr, char direction);

// global variables

extern WINDOW *main_window, *top_window;
extern WINDOW *data_source_win, *data_dest_win, *data_source, *data_dest, *win_pointer;

extern int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2;
extern int W_BOTTOMY2;

WINDOW *filter_window, *f_win;;

int Fil_Number;
int Fil_Base_Pointer = 0;
int Fil_Pointer = 0;

//---------------------------


void Interface_Inject_Redraw(void)
{

#ifdef DEBUG
   Debug_msg("Interface_Inject_Redraw");
#endif

   Interface_Sniff_Data_Redraw();
   doupdate();
}


void Interface_Inject_SetFilter_Redraw(void)
{

#ifdef DEBUG
   Debug_msg("Interface_Inject_SetFilter_Redraw");
#endif

   Interface_Redraw();

   touchwin(f_win);
   touchwin(filter_window);
   wnoutrefresh(f_win);
   wnoutrefresh(filter_window);
   doupdate();
}



int Interface_Inject_Run(u_char *inject_data, char proto, char *app)
{
   WINDOW *inject_window, *i_win;
   int dimY = 10;
   int dimX = 60;
   char inject_sequence[MAX_INJECT];
   int len;

#ifdef DEBUG
   Debug_msg("Interface_Inject_Run -- %c %s", proto, app);
#endif

   i_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   inject_window = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(i_win, COLOR_PAIR(HELP_COLOR));
   wattron(i_win, A_BOLD);
   box(i_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(i_win,  0, 2, "Type characters to be injected (max %d):", MAX_INJECT);
   wbkgdset(inject_window, COLOR_PAIR(BOTTOM_COLOR));
   wmove(inject_window, 0, 0);
   echo();
   scrollok(inject_window, TRUE);
   keypad(inject_window, TRUE);
   curs_set(TRUE);
   wnoutrefresh(i_win);
   wnoutrefresh(inject_window);
   doupdate();

   wmove(inject_window, 1, 0);
   wgetnstr(inject_window, inject_sequence, MAX_INJECT-1);

#ifdef DEBUG
   Debug_msg("Interface_Inject_Run -- inject_sequence len -- [%d]", strlen(inject_sequence));
#endif

   noecho();
   curs_set(FALSE);
   delwin(i_win);
   delwin(inject_window);
   doupdate();

   len = FilterDrop_strescape(inject_data, inject_sequence);

#ifdef DEBUG
   Debug_msg("Interface_Inject_Run -- inject_data len -- [%d]", len);
#endif

   return len;

}


void Interface_Inject_FilterTopStatus(void)
{
   wbkgdset(top_window, COLOR_PAIR(HELP_COLOR));
   mvwprintw(top_window, 0, 31, "Filter: ");

   if (filter_on_source || filter_on_dest)
   {
      wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
      mvwprintw(top_window, 0, 40, "ON ");
   }
   else
   {
      wbkgdset(top_window, COLOR_PAIR(BOTTOM_COLOR));
      mvwprintw(top_window, 0, 40, "OFF");
   }

   wnoutrefresh(top_window);
   doupdate();
}



void Interface_Inject_FilterStatus(void)
{

#ifdef DEBUG
   Debug_msg("Interface_Inject_FilterStatus -- source %d : dest %d", filter_on_source, filter_on_dest);
#endif

   wbkgdset(filter_window, COLOR_PAIR(HELP_COLOR));
   mvwprintw(filter_window,  4, 6, "S] Filters on Source : ");
   wbkgdset(filter_window, COLOR_PAIR(BOTTOM_COLOR));
   switch(filter_on_source)
   {
      case 1:  mvwprintw(filter_window, 4, 29, "ON ");
               break;

      case 0:  mvwprintw(filter_window, 4, 29, "OFF");
               break;
   }
   wbkgdset(filter_window, COLOR_PAIR(HELP_COLOR));
   mvwprintw(filter_window,  6, 6, "D] Filters on Dest   : ");
   wbkgdset(filter_window, COLOR_PAIR(BOTTOM_COLOR));
   switch(filter_on_dest)
   {
      case 1:  mvwprintw(filter_window, 6, 29, "ON ");
               break;

      case 0:  mvwprintw(filter_window, 6, 29, "OFF");
               break;
   }
   wbkgdset(filter_window, COLOR_PAIR(HELP_COLOR));
   Interface_Inject_FilterTopStatus();

   wnoutrefresh(filter_window);
   doupdate();

}



void Interface_Inject_SetFilter(short mode)
{
   int dimY = 15;
   int dimX = 62;
   int KeyPress;

#ifdef DEBUG
   Debug_msg("Interface_Inject_SetFilter");
#endif

   Fil_Number = dimY;

   f_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2 +1);
   filter_window = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +2);
   wbkgdset(f_win, COLOR_PAIR(HELP_COLOR));
   wattron(f_win, A_BOLD);
   box(f_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(f_win,  0, 2, "Filters :");
   wbkgdset(filter_window, COLOR_PAIR(BOTTOM_COLOR));
   wmove(filter_window, 0, 0);
   keypad(filter_window, TRUE);
   wnoutrefresh(f_win);
   doupdate();

   Interface_Inject_FilterStatus();

   wbkgdset(filter_window, COLOR_PAIR(HELP_COLOR));
   mvwprintw(filter_window,  4, 35, "W] Edit filter chain");
   mvwprintw(filter_window,  6, 35, "E] Edit filter chain");

   wnoutrefresh(filter_window);
   doupdate();

   Parser_LoadFilters("");

   loop
   {

skip:

      KeyPress = wgetch(filter_window);

      switch (KeyPress)
      {
         case 'S':
         case 's':
                  if (!filter_on_source && !Filter_Array_Source)
                  {
                     Interface_PopUp("The Source chain is empty !!");
                     Interface_Inject_SetFilter_Redraw();
                  }
                  else if (FilterDrop_CheckMode(Filter_Array_Source, mode))
                  {
                     Interface_PopUp("The chain contains filter(s) that can be used only in ARPBASED mode !!");
                     Interface_Inject_SetFilter_Redraw();
                  }
                  else
                  {
                     if (!filter_on_source)
                        switch(FilterDrop_Validation(Filter_Array_Source))
                        {
                           case 1:
                              Interface_PopUp("CAUTION: the filter chain contains a loop...");
                              Interface_Inject_SetFilter_Redraw();
                              Interface_PopUp("ettercap may hang up. please review your filter chain...");
                              Interface_Inject_SetFilter_Redraw();
                              break;
                           case 2:
                              Interface_PopUp("CAUTION: filter with a jump outside the chain !!!");
                              Interface_Inject_SetFilter_Redraw();
                              Interface_PopUp("ettercap will sig fault. review your filter chain immediately !");
                              Interface_Inject_SetFilter_Redraw();
                              goto skip;
                              break;
                        }
                     filter_on_source = (filter_on_source) ? 0 : 1;
                  }

                  Interface_Inject_FilterStatus();
               break;

         case 'D':
         case 'd':
                  if (!filter_on_dest && !Filter_Array_Dest)
                  {
                     Interface_PopUp("The Dest chain is empty !!");
                     Interface_Inject_SetFilter_Redraw();
                  }
                  else if (FilterDrop_CheckMode(Filter_Array_Dest, mode))
                  {
                     Interface_PopUp("The chain contains filter(s) that can be used only in ARPBASED mode !!");
                     Interface_Inject_SetFilter_Redraw();
                  }
                  else
                  {
                     if (!filter_on_dest)
                        switch(FilterDrop_Validation(Filter_Array_Dest))
                        {
                           case 1:
                              Interface_PopUp("CAUTION: the filter chain contains a loop...");
                              Interface_Inject_SetFilter_Redraw();
                              Interface_PopUp("ettercap may hang up. please review your filter chain...");
                              Interface_Inject_SetFilter_Redraw();
                              break;
                           case 2:
                              Interface_PopUp("CAUTION: filter with a jump outside the chain !!!");
                              Interface_Inject_SetFilter_Redraw();
                              Interface_PopUp("ettercap will sig fault. review your filter chain immediately !");
                              Interface_Inject_SetFilter_Redraw();
                              goto skip;
                              break;
                        }
                     filter_on_dest = (filter_on_dest) ? 0 : 1;
                  }

                  Interface_Inject_FilterStatus();
               break;

         case 'W':
         case 'w':
                  filter_on_source = 0;
                  Interface_Inject_EditFilters(Filter_Array_Source);
                     switch(FilterDrop_Validation(Filter_Array_Source))
                     {
                        case 1:
                           Interface_PopUp("CAUTION: the source filter chain contains a loop...");
                           Interface_Inject_SetFilter_Redraw();
                           Interface_PopUp("ettercap may hang up. please review your filter chain...");
                           Interface_Inject_SetFilter_Redraw();
                           break;
                        case 2:
                           Interface_PopUp("CAUTION: filter with a jump outside the chain !!!");
                           Interface_Inject_SetFilter_Redraw();
                           Interface_PopUp("ettercap will sig fault. review your filter chain immediately !");
                           Interface_Inject_SetFilter_Redraw();
                           goto skip;
                           break;
                     }
                  wbkgdset(filter_window, COLOR_PAIR(HELP_COLOR));
                  werase(filter_window);
                  Interface_Inject_FilterStatus();
                  mvwprintw(filter_window,  4, 33, "W] Edit filter chain");
                  mvwprintw(filter_window,  6, 33, "E] Edit filter chain");
                  wnoutrefresh(filter_window);
                  doupdate();
               break;

         case 'E':
         case 'e':
                  filter_on_dest = 0;
                  Interface_Inject_EditFilters(Filter_Array_Dest);
                     switch(FilterDrop_Validation(Filter_Array_Dest))
                     {
                        case 1:
                           Interface_PopUp("CAUTION: the dest filter chain contains a loop...");
                           Interface_Inject_SetFilter_Redraw();
                           Interface_PopUp("ettercap may hang up. please review your filter chain...");
                           Interface_Inject_SetFilter_Redraw();
                           break;
                        case 2:
                           Interface_PopUp("CAUTION: filter with a jump outside the chain !!!");
                           Interface_Inject_SetFilter_Redraw();
                           Interface_PopUp("ettercap will sig fault. review your filter chain immediately !");
                           Interface_Inject_SetFilter_Redraw();
                           goto skip;
                           break;
                     }
                  wbkgdset(filter_window, COLOR_PAIR(HELP_COLOR));
                  werase(filter_window);
                  Interface_Inject_FilterStatus();
                  mvwprintw(filter_window,  4, 33, "W] Edit filter chain");
                  mvwprintw(filter_window,  6, 33, "E] Edit filter chain");
                  wnoutrefresh(filter_window);
                  doupdate();
               break;

         case KEY_CTRL_L:  // CTRL+L refresh the screen
                  Interface_Inject_SetFilter_Redraw();
                  break;

         case KEY_F(10):
         case 'Q':
         case 'q':
                  delwin(f_win);
                  delwin(filter_window);
                  doupdate();
                  return;
               break;
      }
   }

}



#ifdef HAVE_FORM


int Interface_Inject_Filter(DROP_FILTER *filters)
{
   WINDOW *w;
   FORM *form;
   FIELD *f[18];
   int finished = 0, c;
   unsigned n = 0;
   int status = 0;
   char tmp[10];

#ifdef DEBUG
   Debug_msg("Interface_Inject_Filter");
#endif

   refresh();

   f[n++] = make_label(1, 0, "Proto :");
   f[n++] = make_field(1, 8, 1, 3, FALSE);
   f[n++] = make_label(1, 12, "Source port :");
   f[n++] = make_field(1, 26, 1, 5, FALSE);
   f[n++] = make_label(1, 33, "Dest port :");
   f[n++] = make_field(1, 45, 1, 5, FALSE);
   f[n++] = make_label(3, 0, "Search :");
   f[n++] = make_field(4, 0, 4, MAX_FILTER/4, FALSE);
   f[n++] = make_label(9, 0, "Action (Drop/Replace/Log) :");
   f[n++] = make_field(9, 28, 1, 7, FALSE);
   f[n++] = make_label(11, 0, "Replace :");
   f[n++] = make_field(12, 0, 4, MAX_FILTER/4, FALSE);
   f[n++] = make_label(17, 0, "Goto if match         :");
   f[n++] = make_field(17, 24, 1, 3, FALSE);
   f[n++] = make_label(18, 0, "Goto if doesn't match :");
   f[n++] = make_field(18, 24, 1, 3, FALSE);
   f[n++] = (FIELD *)0;

   form = new_form(f);
   display_form(form);
   w = form_win(form);

   if (filters[Fil_Pointer].proto == 'T')
      sprintf(tmp, "TCP");
   else if (filters[Fil_Pointer].proto == 'U')
      sprintf(tmp, "UDP");
   set_field_buffer(f[1], 0, tmp);

   snprintf(tmp, sizeof(tmp), "%d",  filters[Fil_Pointer].source);
   set_field_buffer(f[3], 0, tmp);
   snprintf(tmp, sizeof(tmp), "%d",  filters[Fil_Pointer].dest);
   set_field_buffer(f[5], 0, tmp);
   set_field_buffer(f[7], 0, filters[Fil_Pointer].display_search);
   snprintf(tmp, sizeof(tmp), "%c",  filters[Fil_Pointer].type);
   set_field_buffer(f[9], 0, tmp);
   set_field_buffer(f[11], 0, filters[Fil_Pointer].display_replace);

   snprintf(tmp, sizeof(tmp), "%d",  filters[Fil_Pointer].go_to);
   if (!strcmp(tmp, "-1"))
      set_field_buffer(f[13], 0, "   ");
   else
      set_field_buffer(f[13], 0, tmp);

   snprintf(tmp, sizeof(tmp), "%d",  filters[Fil_Pointer].else_go_to);
   if (!strcmp(tmp, "-1"))
      set_field_buffer(f[15], 0, "   ");
   else
   set_field_buffer(f[15], 0, tmp);


   curs_set(1);
   form_driver(form, REQ_OVL_MODE);
   finished = get_form_data(form, w);
   erase_form(form);
   free_form(form);

   if (finished == 2)
   {
      char tmp_search[MAX_FILTER+1];

      pthread_mutex_lock(&filter_mutex);

      memset(&filters[Fil_Pointer], 0, sizeof(DROP_FILTER));

      memcpy(&filters[Fil_Pointer].proto, field_buffer(f[1], 0), 1);
      filters[Fil_Pointer].proto = toupper(filters[Fil_Pointer].proto);

      filters[Fil_Pointer].source = atoi(field_buffer(f[3], 0));
      filters[Fil_Pointer].dest = atoi(field_buffer(f[5], 0));

      memcpy(&filters[Fil_Pointer].display_search, field_buffer(f[7], 0), MAX_FILTER);
      trim_buffer(filters[Fil_Pointer].display_search, ' ');
      filters[Fil_Pointer].wildcard = FilterDrop_ParseWildcard(tmp_search, filters->display_search, sizeof(tmp_search));
      filters[Fil_Pointer].slen = FilterDrop_strescape(filters[Fil_Pointer].search, tmp_search);

      memcpy(&filters[Fil_Pointer].display_replace, field_buffer(f[11], 0), MAX_FILTER);
      trim_buffer(filters[Fil_Pointer].display_replace, ' ');
      filters[Fil_Pointer].rlen = FilterDrop_strescape(filters[Fil_Pointer].replace, filters[Fil_Pointer].display_replace);

      memcpy(&filters[Fil_Pointer].type, field_buffer(f[9], 0), 1);
      filters[Fil_Pointer].type = toupper(filters[Fil_Pointer].type);

      if (!strcmp(field_buffer(f[13], 0), "   "))
         filters[Fil_Pointer].go_to = -1;
      else
         filters[Fil_Pointer].go_to = atoi(field_buffer(f[13], 0));

      if (!strcmp(field_buffer(f[15], 0), "   "))
         filters[Fil_Pointer].else_go_to = -1;
      else
         filters[Fil_Pointer].else_go_to = atoi(field_buffer(f[15], 0));

      pthread_mutex_unlock(&filter_mutex);

      status = 1;
   }

   for (c = 0; f[c] != 0; c++)
      free_field(f[c]);

   curs_set(0);

   return status;
}

#else    // DOESN'T HAVE_FORM

int Interface_Inject_Filter(DROP_FILTER *filters)
{
   WINDOW *edit_window, *e_win;
   int dimY = 18;
   int dimX = 50;
   char tmp[10];
   char tmp_search[MAX_FILTER+1];

#ifdef DEBUG
   Debug_msg("Interface_Inject_Filter -- NO FORM");
#endif

   e_win = newwin(dimY+2, dimX+2, W_BOTTOMY2/2 - dimY/2, W_MAINX2/2 - dimX/2);
   edit_window = newwin(dimY, dimX, W_BOTTOMY2/2 - dimY/2 +1, W_MAINX2/2 - dimX/2 +1);
   wbkgdset(e_win, COLOR_PAIR(HELP_COLOR));
   wattron(e_win, A_BOLD);
   box(e_win,ACS_VLINE,ACS_HLINE);
   mvwprintw(e_win,  0, 2, "Define a filter:", MAX_INJECT);
   wbkgdset(edit_window, COLOR_PAIR(BOTTOM_COLOR));
   wmove(edit_window, 0, 0);
   echo();
   scrollok(edit_window, TRUE);
   keypad(edit_window, TRUE);
   curs_set(TRUE);

   wprintw(edit_window, "\nProtocol (Tcp/Udp) : ");
      wnoutrefresh(e_win);
      wnoutrefresh(edit_window);
      doupdate();
   wgetnstr(edit_window, tmp, 3);
   filters[Fil_Pointer].proto = toupper(tmp[0]);

   wprintw(edit_window, "Source Port : ");
      wnoutrefresh(e_win);
      wnoutrefresh(edit_window);
      doupdate();
   wgetnstr(edit_window, tmp, 5);
   filters[Fil_Pointer].source = atoi(tmp);


   wprintw(edit_window, "Dest Port : ");
      wnoutrefresh(e_win);
      wnoutrefresh(edit_window);
      doupdate();
   wgetnstr(edit_window, tmp, 5);
   filters[Fil_Pointer].dest = atoi(tmp);

   wprintw(edit_window, "Search : ");
      wnoutrefresh(e_win);
      wnoutrefresh(edit_window);
      doupdate();
   wgetnstr(edit_window, filters[Fil_Pointer].display_search, MAX_FILTER-1);
   filters[Fil_Pointer].wildcard = FilterDrop_ParseWildcard(tmp_search, filters[Fil_Pointer].display_search, sizeof(tmp_search));
   filters[Fil_Pointer].slen = FilterDrop_strescape(filters[Fil_Pointer].search, tmp_search);

   wprintw(edit_window, "\nAction (Drop/Replace/Log) : ");
      wnoutrefresh(e_win);
      wnoutrefresh(edit_window);
      doupdate();
   wgetnstr(edit_window, tmp, 7);
   filters[Fil_Pointer].type = toupper(tmp[0]);

   if (filters[Fil_Pointer].type == 'R')
   {
      wprintw(edit_window, "\nReplace : ");
         wnoutrefresh(e_win);
         wnoutrefresh(edit_window);
         doupdate();
      wgetnstr(edit_window, filters[Fil_Pointer].display_replace, MAX_FILTER-1);
      filters[Fil_Pointer].rlen = FilterDrop_strescape(filters[Fil_Pointer].replace, filters[Fil_Pointer].display_replace);
   }


   wprintw(edit_window, "Goto if match : ");
      wnoutrefresh(e_win);
      wnoutrefresh(edit_window);
      doupdate();
   wgetnstr(edit_window, tmp, 3);
   if (!strcmp(tmp, ""))
      filters[Fil_Pointer].go_to = -1;
   else
      filters[Fil_Pointer].go_to = atoi(tmp);


   wprintw(edit_window, "Goto if doesn't match : ");
      wnoutrefresh(e_win);
      wnoutrefresh(edit_window);
      doupdate();
   wgetnstr(edit_window, tmp, 3);
   if (!strcmp(tmp, ""))
      filters[Fil_Pointer].else_go_to = -1;
   else
      filters[Fil_Pointer].else_go_to = atoi(tmp);

   noecho();
   curs_set(FALSE);
   delwin(e_win);
   delwin(edit_window);
   doupdate();

   return 1;
}

#endif   // HAVE_FORM





void Interface_Inject_EditFilters_InitList(DROP_FILTER *FA_ptr)
{

   int j;
   int Fil_Top_Pointer, num_filter, LeftMargin = 1;

   if (has_colors())
      wbkgdset(filter_window, COLOR_PAIR(HELP_COLOR));
   else
      wattroff(filter_window,A_REVERSE);

   werase(filter_window);

   if (FA_ptr == Filter_Array_Source)
      num_filter = Filter_Source;
   else
      num_filter = Filter_Dest;

   if (num_filter == 0)
   {
      mvwprintw(filter_window,  4, 19, "NO FILTER IN THIS CHAIN");
      mvwprintw(filter_window,  10, 15, "Press 'a' to add or 'h' for help");
      wnoutrefresh(filter_window);
      doupdate();
      return;
   }

   if (Fil_Pointer >= num_filter) Fil_Pointer = num_filter-1;

   Fil_Top_Pointer = (Fil_Base_Pointer+Fil_Number < num_filter) ? Fil_Base_Pointer + Fil_Number : num_filter ;

   for(j=Fil_Base_Pointer; j<Fil_Top_Pointer; j++)
   {
      wmove(filter_window, j-Fil_Base_Pointer, LeftMargin );
      wprintw(filter_window, "%s", Parser_PrintFilter(FA_ptr, j));
   }

   if (has_colors())
      wbkgdset(filter_window, COLOR_PAIR(POINT_COLOR));
   else
      wattron(filter_window,A_REVERSE);


   wmove(filter_window, Fil_Pointer - Fil_Base_Pointer, LeftMargin );
   whline(filter_window, ' ', 60);
   wprintw(filter_window, "%s", Parser_PrintFilter(FA_ptr, Fil_Pointer));

   wnoutrefresh(filter_window);
   doupdate();

}


void Interface_Inject_EditFilters_PointItem(DROP_FILTER *FA_ptr, char direction)
{

   int Old_Fil_Pointer, num_filter, LeftMargin = 1;;

   if (FA_ptr == Filter_Array_Source)
      num_filter = Filter_Source;
   else
      num_filter = Filter_Dest;

   if (num_filter == 0) return;

   Old_Fil_Pointer = Fil_Pointer;

   Fil_Pointer += direction;

   if (Fil_Pointer > num_filter -1 ) Fil_Pointer = num_filter - 1;
   if (Fil_Pointer < 0) Fil_Pointer = 0;


   if ( (Fil_Pointer - Fil_Base_Pointer + direction  >= Fil_Number) && (direction > 0) )      // scroll down
   {
      if (Fil_Base_Pointer + Fil_Number <= num_filter)
         Fil_Base_Pointer = (Fil_Base_Pointer + direction < num_filter) ? Fil_Base_Pointer + direction : num_filter - Fil_Number;

      Interface_Inject_EditFilters_InitList(FA_ptr);
   }
   else if ( (Fil_Pointer - Fil_Base_Pointer + direction < 0) && (direction < 0) )         // scroll up
   {
      if (Fil_Base_Pointer > 0)
         Fil_Base_Pointer = (Fil_Base_Pointer + direction > 0) ? Fil_Base_Pointer + direction : 0;

      Interface_Inject_EditFilters_InitList(FA_ptr);
   }


   if (has_colors())
      wbkgdset(filter_window, COLOR_PAIR(HELP_COLOR));
   else
      wattroff(filter_window,A_REVERSE);


   if ( (Old_Fil_Pointer >= Fil_Base_Pointer) && (Old_Fil_Pointer <= Fil_Base_Pointer + Fil_Number -1)) // DON'T redraw previous selected item if it is out of view
   {
      wmove(filter_window, Old_Fil_Pointer - Fil_Base_Pointer, LeftMargin);
      whline(filter_window,' ', 60);                         //deletes the previous position
      wprintw(filter_window, "%s", Parser_PrintFilter(FA_ptr, Old_Fil_Pointer));
   }

   if (has_colors())
      wbkgdset(filter_window, COLOR_PAIR(POINT_COLOR));
   else
      wattron(filter_window,A_REVERSE);

   wmove(filter_window, Fil_Pointer - Fil_Base_Pointer, LeftMargin);
   whline(filter_window, ' ', 60);                           //select new position

   wprintw(filter_window, "%s", Parser_PrintFilter(FA_ptr, Fil_Pointer));

   wnoutrefresh(filter_window);
   doupdate();
}




void Interface_Inject_EditFilters(DROP_FILTER *FA_ptr)
{
   int KeyPress;

#ifdef DEBUG
   Debug_msg("Interface_Inject_EditFilters");
#endif

   werase(filter_window);
   wmove(filter_window, 0, 0);
   wnoutrefresh(filter_window);
   doupdate();

   Fil_Pointer = Fil_Base_Pointer = 0;

   Interface_Inject_EditFilters_InitList(FA_ptr);

   loop
   {
      KeyPress = wgetch(filter_window);

      switch (KeyPress)
      {
         case KEY_DOWN:
                  Interface_Inject_EditFilters_PointItem(FA_ptr, 1);
                  break;

         case KEY_UP:
                  Interface_Inject_EditFilters_PointItem(FA_ptr, -1);
                  break;

         case KEY_NPAGE:
                  Interface_Inject_EditFilters_PointItem(FA_ptr, Fil_Number-1);  //PGDOWN
                  break;

         case KEY_PPAGE:
                  Interface_Inject_EditFilters_PointItem(FA_ptr, -Fil_Number+1); //PGUP
                  break;

         case KEY_RETURN:
                  Interface_Inject_Filter(FA_ptr);
                  Interface_Inject_SetFilter_Redraw();
                  if (FA_ptr[Fil_Pointer].slen == 0 && FA_ptr[Fil_Pointer].type == 'R')
                  {
                     Interface_PopUp("NOT a good idea setting a zero length search string with Replace method...");
                     Interface_Inject_SetFilter_Redraw();
                     Interface_PopUp("please re-Edit this filter or ettercap will hang up on it !!");
                     Interface_Inject_SetFilter_Redraw();
                     if (FA_ptr == Filter_Array_Source)  // safe disable the filter chain
                        filter_on_source = 0;
                     else
                        filter_on_dest = 0;
                  }
                  Interface_Inject_EditFilters_InitList(FA_ptr);
                  break;

         case 'A':
         case 'a':
                  if (FA_ptr == Filter_Array_Source)
                  {
                     FilterDrop_AddFilter(Filter_Array_Source);
                     FA_ptr = Filter_Array_Source;
                  }
                  else if (FA_ptr == Filter_Array_Dest)
                  {
                     FilterDrop_AddFilter(Filter_Array_Dest);
                     FA_ptr = Filter_Array_Dest;
                  }
                  Interface_Inject_EditFilters_InitList(FA_ptr);
                  break;

         case 'D':
         case 'd':
                  FilterDrop_DelFilter(FA_ptr, Fil_Pointer);
                  Interface_Inject_EditFilters_InitList(FA_ptr);
                  break;

         case 'S':
         case 's':
                  FilterDrop_SaveFilter();
                  Interface_PopUp("Filter chain saved !");
                  Interface_Inject_SetFilter_Redraw();
                  break;

         case KEY_CTRL_L:  // CTRL+L refresh the screen
                  Interface_Inject_SetFilter_Redraw();
                  break;

         case KEY_F(1):
         case 'H':
         case 'h':{
                     static char *help[] = {
                        "[qQ][F10] - quit",
                        "[return]  - edit the selected filter",
                        "[dD]      - Delete the filter",
                        "[aA]      - Add a new filter",
                        "[sS]      - Save the filters chain",
                        NULL};
                     Interface_HelpWindow(help);
                  }
                  Interface_Inject_SetFilter_Redraw();
                  break;

         case KEY_F(10):
         case 'Q':
         case 'q':
                  if (Interface_PopUp("Do you want to save the filters chain (y/n)?")=='y')
                     FilterDrop_SaveFilter();

                  Parser_LoadFilters("");
                  Interface_Inject_SetFilter_Redraw();
                  return;
                  break;
      }

   }

}



#endif

/* EOF */
