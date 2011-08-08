/*
    ettercap -- error handling module

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

    $Id: ec_error.c,v 1.6 2001/12/08 11:22:20 alor Exp $
*/

#include "include/ec_main.h"

#include <stdarg.h>
#include <errno.h>


#ifdef HAVE_NCURSES
    #include "include/ec_interface.h"
#endif

// protos

void Error_msg(char *message, ...);
void Error_critical_msg(char *file, char *function, int line, char *message);

// ------------------------------

void Error_msg(char *message, ...)
{
   va_list ap;
   char errmsg[201];    // should be enough

   va_start(ap, message);
   vsnprintf(errmsg, 200, message, ap);
   va_end(ap);

#ifdef DEBUG
   Debug_msg("Error_msg -- %s", errmsg);
#endif

#ifdef HAVE_NCURSES
   if (!Options.normal)
      Interface_WExit(errmsg);
#endif

   fprintf(stderr, "\n\n%s\n\n", errmsg);
   exit(-1);
}


void Error_critical_msg(char *file, char *function, int line, char *message)
{
   char err[201];

   snprintf(err, 200, "[%s:%s:%d] %s | ERRNO %d | %s", file, function, line, message, errno, strerror(errno));
   err[200] = 0;

#ifdef DEBUG
      Debug_msg("Error_msg -- %s",  err);
#endif

#ifdef HAVE_NCURSES
   if (!Options.normal)
      Interface_WExit(err);
#endif

   fprintf(stderr, "\n\n%s\n\n", err);
   exit(-1);
}


/* EOF */
