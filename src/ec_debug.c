/*
    ettercap -- debug module

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

    $Id: ec_debug.c,v 1.5 2001/12/08 11:22:20 alor Exp $
*/

#include "include/ec_main.h"

#ifdef DEBUG

#include <stdarg.h>
#ifdef HAVE_SYS_UTSNAME_H
   #include <sys/utsname.h>
   #ifdef LINUX
      #include <features.h>
   #endif
#endif
#ifdef HAVE_NCURSES
   #ifdef HAVE_NCURSES_H
      #include <ncurses.h>
   #else
      #include <curses.h>
   #endif
#endif

#ifndef DEBUG_FILE
   #define DEBUG_FILE "ettercap_debug.log"
#endif

#include "include/ec_thread.h"

FILE *debug_dev;

void Debug_Init(void);
void Debug_Close(void);
void Debug_msg(char *message, ...);

//----------------------------

void Debug_Init(void)
{
   struct utsname buf;

   if ((debug_dev = fopen (DEBUG_FILE, "a")) < 0)
   {
      fprintf(stderr, "Couldn't open DEBUG FILE!\n");
      exit(0);
   }
   else
   {
      fprintf (debug_dev, "\n\n-> %s %s\n\n", PROGRAM, VERSION);
      #ifdef HAVE_SYS_UTSNAME_H
         uname(&buf);
         #if defined (__GLIBC__) && defined (__GLIBC_MINOR__)
            fprintf (debug_dev, "-> running on %s %s  glibc %d.%d\n",  buf.sysname, buf.release, __GLIBC__, __GLIBC_MINOR__);
         #else
            fprintf (debug_dev, "-> running on %s %s\n", buf.sysname, buf.release);
         #endif
      #endif
      #if defined (__GNUC__) && defined (__GNUC_MINOR__)
         fprintf (debug_dev, "-> compiled with gcc %d.%d\n", __GNUC__, __GNUC_MINOR__);
      #endif
      #ifdef HAVE_NCURSES
         fprintf (debug_dev, "-> %s\n", curses_version());
      #endif
      fprintf (debug_dev, "\n\nDEVICE OPENED FOR %s DEBUGGING\n\n", PROGRAM);
      fflush(debug_dev);
      atexit(Debug_Close);
   }
}



void Debug_Close(void)
{
   fprintf (debug_dev, "\n\nDEBUGGING DEVICE FOR %s WAS CLOSED\n\n", ECThread_getname(pthread_self()));
   fclose (debug_dev);
}



void Debug_msg(char *message, ...)
{

   va_list ap;
   char debug_message[strlen(message)+2];

   fprintf (debug_dev, "%-10s\t", ECThread_getname(pthread_self()));

   strlcpy(debug_message, message, sizeof(debug_message)); // for backward compatibility
   strlcat(debug_message, "\n", sizeof(debug_message));

   va_start(ap, message);
   vfprintf(debug_dev, debug_message, ap);
   va_end(ap);

   fflush(debug_dev);

}

#endif

/* EOF */
