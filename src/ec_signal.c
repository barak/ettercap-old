/*
    ettercap -- signal handler

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

    $Id: ec_signal.c,v 1.4 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#include <signal.h>

#ifndef CYGWIN
	#include <sys/resource.h>
#endif



#ifdef HAVE_NCURSES
   #ifdef HAVE_NCURSES_H
      #include <ncurses.h>
   #else
      #include <curses.h>
   #endif
   #include "include/ec_interface.h"
   #include "include/ec_interface_sniff_data.h"
   #include "include/ec_interface_plugins.h"

   extern WINDOW *data_source_win;
   extern WINDOW *plugin_window;
   extern short ScreenMode;

   #ifdef HAVE_TERMIOS_H
      #ifdef CYGWIN
         #undef FIONBIO
      #endif
      #include <termios.h>
      extern struct termios original_term_info;
   #endif
#endif

#include "include/ec_error.h"
#include "include/ec_thread.h"

// protos...

void Signal_SigBuster(void);
RETSIGTYPE Signal_SEGV(int sig);
RETSIGTYPE Signal_TERM(int sig);
RETSIGTYPE Signal_WINCH(int sig);

//-----------------------

void Signal_SigBuster(void)
{
#ifdef DEBUG
   Debug_msg("Signal_Buster");
#endif

   signal(SIGBUS,  Signal_SEGV);
   signal(SIGSEGV,  Signal_SEGV);
   signal(SIGHUP,   Signal_TERM);
   signal(SIGTERM,  Signal_TERM);
   signal(SIGWINCH, Signal_WINCH);
   signal(SIGCHLD,  SIG_IGN);       // if I kill a forked process it doesn't become a zombie...
   signal(SIGPIPE,  Signal_TERM);   // if ettercap SIGSEGV, illithid receives this sig... (pipe_with_illithid)

}


RETSIGTYPE Signal_SEGV(int sig)
{
#ifdef DEBUG

#ifndef CYGWIN
   struct rlimit corelimit = {RLIM_INFINITY, RLIM_INFINITY};
#endif

   if (sig == SIGBUS)
      Debug_msg("[%s] Bus Error...", ECThread_getname(pthread_self()) );
   else if (sig == SIGSEGV)
      Debug_msg("[%s] Segmentation Fault...", ECThread_getname(pthread_self()) );
#endif

#ifdef HAVE_NCURSES
   if (ScreenMode)    // close the ncurses screen
      Interface_CloseScreen();
#endif


   fprintf (stderr, "\n\033[01m\033[1m Ooops !! Somewhere in the stack a pointer got crazy...\n\n");
   if (sig == SIGBUS)
      fprintf (stderr, " [%s] Bus Error...\033[0m\n\n\n", ECThread_getname(pthread_self()));
   else if (sig == SIGSEGV)
      fprintf (stderr, " [%s] Segmentation Fault...\033[0m\n\n", ECThread_getname(pthread_self()));

   fprintf (stderr, "===========================================================================\n");
   fprintf (stderr, " To report this error follow these steps:\n\n");
#ifndef DEBUG
   fprintf (stderr, "  1) recompile ettercap in debug mode : \n"
                    "  \t\"configure --enable-debug && make clean && make\"\n\n");
   fprintf (stderr, "  2) reproduce the critical situation\n\n");
#else
   fprintf (stderr, "  1) and 2) already done...\n\n");
#endif
   if (sig == SIGBUS)
   {
      fprintf (stderr, "  3) make a report : \"tar zcvf error.tar.gz ettercap_debug.log\"\n\n");
      fprintf (stderr, "  4) mail us the error.tar.gz\n\n\n\n");
      exit(666);
   }

   fprintf (stderr, "  3) make a report : \"tar zcvf error.tar.gz ettercap_debug.log \"\n\n");
   fprintf (stderr, "  4) get the gdb backtrace :\n"
                    "  \t - \"gdb ettercap core\"\n"
                    "  \t - at the gdb prompt \"bt\"\n"
                    "  \t - at the gdb prompt \"quit\" and return to the shell\n"
                    "  \t - copy and paste this output.\n\n");
   fprintf (stderr, "  5) mail us the output of gdb and the error.tar.gz\n");
   fprintf (stderr, "============================================================================\n");

#ifndef DEBUG
   exit(666);
#else // DEBUGGING MODE
   fprintf(stderr, "\n\033[01m\033[1m Overriding any 'ulimit -c 0'...\n"
                   " Setting core size to RLIM_INFINITY...\n\n"
                   " Core dumping... (use the 'core' file for gdb analysis)\033[0m\n\n");
#ifndef CYGWIN
   setrlimit(RLIMIT_CORE, &corelimit);
#endif

   signal(sig, SIG_DFL);
   raise(sig);
#endif
}



RETSIGTYPE Signal_TERM(int sig)
{
#ifdef DEBUG
   #ifdef HAVE_STRSIGNAL
      Debug_msg("[%s] Signal handler... (caught SIGNAL: %d) | %s", ECThread_getname(pthread_self()), sig, strsignal(sig));
   #else
      Debug_msg("[%s] Signal handler... (caught SIGNAL: %d)", ECThread_getname(pthread_self()), sig);
   #endif
#endif


#ifdef HAVE_NCURSES
   if (ScreenMode)
      Interface_CloseScreen();
#endif

   #ifdef HAVE_STRSIGNAL
      printf("\n Signal handler... (caught SIGNAL: %d) | %s\n\n", sig, strsignal(sig));
   #else
      printf("\n Signal handler... (caught SIGNAL: %d)\n\n", sig);
   #endif

   exit(1);

}



RETSIGTYPE Signal_WINCH(int sig)
{

#ifdef HAVE_NCURSES
   if (ScreenMode)
   {
      if (data_source_win != NULL)
      {
         #ifdef DEBUG
            Debug_msg("Winching sniff data windows...");
         #endif
         Interface_Sniff_Data_Winch();
      }
#ifdef PERMIT_PLUGINS
      else if (plugin_window != NULL)
      {
         #ifdef DEBUG
            Debug_msg("Winching plugin windows...");
         #endif
         Interface_Plugins_Winch();
      }
#endif
      else
      {
         #ifdef DEBUG
            Debug_msg("Winching windows...");
         #endif
         Interface_Winch();
      }
   }
#endif
   signal(SIGWINCH, Signal_WINCH);
}


/* EOF */
