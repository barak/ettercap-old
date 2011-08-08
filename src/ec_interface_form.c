/*
    ettercap -- ncurses form handler

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

    $Id: ec_interface_form.c,v 1.2 2001/11/19 09:30:23 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_NCURSES  // don't compile if ncurses interface is not supported
#ifdef HAVE_FORM

#ifdef HAVE_NCURSES_H
	#include <ncurses.h>
#else
	#include <curses.h>
#endif
#ifdef HAVE_CTYPE_H
   #include <ctype.h>
#endif
   #include <form.h>


#include "include/ec_error.h"
#include "include/ec_interface_form.h"


#define BOTTOM_COLOR 1        // color schemes
#define TITLE_COLOR  2
#define MAIN_COLOR   3
#define POINT_COLOR  4
#define SEL_COLOR    5
#define HELP_COLOR   6
#define SNIFF_COLOR  7


// protos...

FIELD *make_label(int frow, int fcol, char *label);
FIELD *make_field(int frow, int fcol, int rows, int cols, bool secure);
void display_form(FORM *f);
void erase_form(FORM *f);
int form_virtualize(FORM *f, WINDOW *w);
int my_form_driver(FORM *form, int c);
int get_form_data(FORM *form, WINDOW *w);
void trim_buffer(char *buffer, char trim);

// global variables

extern WINDOW *main_window;

extern int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2;
extern int W_BOTTOMY2;


//---------------------------



FIELD *make_label(int frow, int fcol, char *label)
{
   FIELD *f = new_field(1, strlen(label), frow, fcol, 0, 0);

   if (f)
   {
      set_field_buffer(f, 0, label);
      set_field_opts(f, field_opts(f) & ~O_ACTIVE);
   }
   return(f);
}

FIELD *make_field(int frow, int fcol, int rows, int cols, bool secure)
{
   FIELD *f = new_field(rows, cols, frow, fcol, 0, secure ? 1 : 0);

   if (f) {
      set_field_back(f, A_UNDERLINE);
      set_field_userptr(f, (void *)0);
      field_opts_off(f, O_WRAP);
   }
   return(f);
}

void display_form(FORM *f)
{
   WINDOW *w;
   int rows, cols;

   scale_form(f, &rows, &cols);

   if ((w = newwin(rows+6, cols+4, W_BOTTOMY2/2 - rows/2 - 3, W_MAINX2/2 - cols/2)) != (WINDOW *)0)
   {
      wbkgdset(w, COLOR_PAIR(HELP_COLOR));
      set_form_win(f, w);
      set_form_sub(f, derwin(w, rows, cols, 1, 2));
      box(w, 0, 0);
      keypad(w, TRUE);
      mvwprintw(w, rows+2, 2, "Enter - set the filter  F10/ESC - exit form");
      mvwprintw(w, rows+3, 2, " ^N   - next field        ^P    - previous field");
      mvwprintw(w, rows+4, 2, " ^H   - del prev char     ^Y    - delete line");
   }

   if (post_form(f) != E_OK)
      wrefresh(w);
}

void erase_form(FORM *f)
{
   WINDOW *w = form_win(f);
   WINDOW *s = form_sub(f);

   unpost_form(f);
   werase(w);
   wrefresh(w);
   delwin(s);
   delwin(w);
}


int form_virtualize(FORM *f, WINDOW *w)
{

// "Defined form-traversal keys:   F10/ESC- exit form"
// "^N   -- go to next field       ^P  -- go to previous field"
// "Home -- go to first field      End -- go to last field"
// "^L   -- go to field to left    ^R  -- go to field to right"
// "^U   -- move upward to field   ^D  -- move downward to field"
// "^W   -- go to next word        ^B  -- go to previous word"
// "^S   -- go to start of field   ^E  -- go to end of field"
// "^H   -- delete previous char   ^Y  -- delete line"
// "^G   -- delete current word    ^C  -- clear to end of line"
// "^K   -- clear to end of field  ^X  -- clear field"


    static const struct {
      int code;
      int result;
    } lookup[] = {
         { CTRL('A'),     REQ_NEXT_CHOICE },
         { CTRL('B'),     REQ_PREV_WORD },
         { CTRL('C'),     REQ_CLR_EOL },
         { CTRL('D'),     REQ_DOWN_FIELD },
         { CTRL('E'),     REQ_END_FIELD },
         { CTRL('F'),     REQ_NEXT_PAGE },
         { CTRL('G'),     REQ_DEL_WORD },
         { CTRL('H'),     REQ_DEL_PREV },
         { CTRL('I'),     REQ_INS_CHAR },
         { CTRL('K'),     REQ_CLR_EOF },
         { CTRL('M'),     REQ_NEW_LINE },
         { CTRL('N'),     REQ_NEXT_FIELD },
         { CTRL('O'),     REQ_INS_LINE },
         { CTRL('P'),     REQ_PREV_FIELD },
         { CTRL('S'),     REQ_BEG_FIELD },
         { CTRL('U'),     REQ_UP_FIELD },
         { CTRL('V'),     REQ_DEL_CHAR },
         { CTRL('W'),     REQ_NEXT_WORD },
         { CTRL('X'),     REQ_CLR_FIELD },
         { CTRL('Y'),     REQ_DEL_LINE },
         { CTRL('Z'),     REQ_PREV_CHOICE },
         { ESCAPE,        MAX_FORM_COMMAND + 1 },
         { KEY_F(10),     MAX_FORM_COMMAND + 1 },
         { KEY_BACKSPACE, REQ_DEL_PREV },
         { KEY_DOWN,      REQ_DOWN_CHAR },
         { KEY_END,       REQ_LAST_FIELD },
         { KEY_HOME,      REQ_FIRST_FIELD },
         { KEY_LEFT,      REQ_LEFT_CHAR },
         { KEY_LL,        REQ_LAST_FIELD },
         { KEY_NEXT,      REQ_NEXT_FIELD },
         { KEY_NPAGE,     REQ_NEXT_PAGE },
         { KEY_PPAGE,     REQ_PREV_PAGE },
         { KEY_PREVIOUS,  REQ_PREV_FIELD },
         { KEY_RIGHT,     REQ_RIGHT_CHAR },
         { KEY_UP,        REQ_UP_CHAR },
         { KEY_RETURN,    MAX_FORM_COMMAND + 2 },
         { QUIT,          MAX_FORM_COMMAND + 1 }
    };

   static int  mode = REQ_INS_MODE;
   int c = wgetch(w);
   unsigned n;
   FIELD *me = current_field(f);

   if (c == CTRL(']') || c == KEY_INS )
   {
      if (mode == REQ_INS_MODE)
         mode = REQ_OVL_MODE;
      else
         mode = REQ_INS_MODE;
      c = mode;
   }
   else
   {
      for (n = 0; n < sizeof(lookup)/sizeof(lookup[0]); n++)
      {
         if (lookup[n].code == c)
         {
            c = lookup[n].result;
            break;
         }
      }
   }

   /*
    * Force the field that the user is typing into to be in reverse video,
    * while the other fields are shown underlined.
    */
   if (c <= KEY_MAX)
      set_field_back(me, A_REVERSE);
   else if (c <= MAX_FORM_COMMAND)
      set_field_back(me, A_UNDERLINE);

   return c;
}

int my_form_driver(FORM *form, int c)
{
   if (c == (MAX_FORM_COMMAND + 1) && form_driver(form, REQ_VALIDATION) == E_OK)
      return(TRUE);
   else if (c == (MAX_FORM_COMMAND + 2) && form_driver(form, REQ_VALIDATION) == E_OK)
      return 2;
   else
   {
      beep();
      return(FALSE);
   }
}

void trim_buffer(char *buffer, char trim)
{
   int i;

   for(i = strlen(buffer)-1; i >= 0; i--)
      if (buffer[i] == trim) buffer[i] = 0;
      else break;

}

int get_form_data(FORM *form, WINDOW *w)
{
   int finished=0, c;

   while (!finished)
   {
      switch(form_driver(form, c = form_virtualize(form, w)))
      {
         case E_OK:
            clrtoeol();
            refresh();
            break;
         case E_UNKNOWN_COMMAND:
            finished = my_form_driver(form, c);
            break;
         default:
            beep();
            break;
      }
   }
   return finished;
}

#endif   // HAVE_FORM
#endif   // HAVE_NCURSES

/* EOF */
