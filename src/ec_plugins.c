/*
    ettercap -- PlugIns module

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

    $Id: ec_plugins.c,v 1.12 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#ifdef PERMIT_PLUGINS   // don't compile if plug-in not supported

#ifdef HAVE_NCURSES
   #ifdef HAVE_NCURSES_H
      #include <ncurses.h>
   #else
      #include <curses.h>
   #endif
   #include "include/ec_interface_plugins.h"

   #define BOTTOM_COLOR 1        // color schemes
   #define HELP_COLOR   6

   extern WINDOW *plugin_window, *main_window;
   extern short scroll_yp;
   extern int W_MAINX1, W_MAINY1, W_MAINX2, W_MAINY2;
#endif


#include <dlfcn.h>
#include <stdarg.h>
#include <dirent.h>

#include "include/ec_plugins.h"
#include "include/ec_error.h"
#include "include/ec_parser.h"
#include "include/ec_queue.h"
#include "include/ec_buffer.h"


#ifdef OPENBSD
// The below define is a lie since we are really doing RTLD_LAZY since the
// system doesn't support RTLD_NOW.
   #define RTLD_NOW DL_LAZY
#endif

struct plug_list
{
   struct plugin_attr plugin;
   LIST_ENTRY(plug_list) next;
};

LIST_HEAD(, plug_list) loaded_plug_list;

struct plug_array *Plugins_Array = NULL;

// protos....

int Plugin_Register(void *, struct plugin_ops *);
void Plugin_LoadAll(void);
int Plugin_Load(char *name, char *path);
int Plugin_UnLoad(char *name);
void Plugin_HookPoint(char hook_point, void *args);
int Plugin_RunExt(char *name);
char * Plugin_Getname(char *file);
char * Plugin_Getfile(char *name, char *path);
char ** Plugin_ExtList(void);
int Plugin_ExtArray(void);
void Plugin_SetActivation(char *name, char status);

int Plugin_Input(char *string, size_t size, short mode);
int Plugin_Input_GetChar_Block(char *string, size_t size);
int Plugin_Input_GetChar_NonBlock(char *string, size_t size);
void Plugin_Output(char *message, ...);
void Plugin_Hook_Output(char *message, ...);
void Plugin_SYS_Output(char *message, ...);

// --------------------------


int Plugin_Register(void *plug, struct plugin_ops *ops)
{
   struct plug_list *ptr = (struct plug_list *)plug;

   if (strcmp(ops->ettercap_version, VERSION))     // compiled under different ettercap version
      return 0;


   if (ops->hook_function == NULL)                 // where is the hook function ?
      return 0;


   memcpy(&ptr->plugin.ops, ops, sizeof(struct plugin_ops));
   ptr->plugin.ops.plug_info = strdup(ops->plug_info);

   return 1;
}



void Plugin_LoadAll(void)
{
   struct plug_list *current;
   struct dirent **namelist;
   int n, i;

#ifdef DEBUG
   Debug_msg("Plugin_LoadAll -- %s", PLUGIN_PATH);
#endif

   fprintf (stdout, "\nLoading plugins... ");
   fflush (stdout);

   n = scandir(".", &namelist, 0, alphasort);

   for(i=n-1; i>=0; i--)
     if ( match_pattern(namelist[i]->d_name, "ec_*.so") )
     {
         if ( Plugin_Load(Plugin_Getname(namelist[i]->d_name), ".") == 0)
            fprintf (stdout, "\n./%s contains errors !",namelist[i]->d_name);
         fflush (stdout);
     }

   n = scandir(PLUGIN_PATH, &namelist, 0, alphasort);

   for(i=n-1; i>=0; i--)
     if ( match_pattern(namelist[i]->d_name, "ec_*.so") )
     {
         switch( Plugin_Load(Plugin_Getname(namelist[i]->d_name), PLUGIN_PATH) )
         {
            case 0:
                     fprintf (stdout, "\n%s/%s contains errors !", PLUGIN_PATH, namelist[i]->d_name);
                     break;
            case -1:
                     fprintf (stdout, "\n%s/%s already loaded !", PLUGIN_PATH, namelist[i]->d_name);
                     break;
         }
         fflush (stdout);
      }

   fprintf (stdout, "Done.\n");

   LIST_FOREACH(current, &loaded_plug_list, next)        // unload external plugins....
   {
      if (current->plugin.ops.plug_type == PT_EXT)
      {
         #ifdef DEBUG
            Debug_msg("Plugin_LoadAll - Unloading external - %s", current->plugin.name);
         #endif
         (current->plugin.fini_function)(NULL);
         dlclose(current->plugin.handle);
         current->plugin.handle = NULL;
      }
   }

}



int Plugin_Load(char *name, char *path)
{
   struct plug_list *current;

#ifdef DEBUG
      Debug_msg("Plugin_Load -- %s%s", path, name);
#endif

   LIST_FOREACH(current, &loaded_plug_list, next)
   {
      if (!strcmp(current->plugin.name, name) && current->plugin.handle != NULL)
         return -1; // already loaded
   }

   current = (struct plug_list *)calloc(1, sizeof(struct plug_list));
   if (!current)
      ERROR_MSG("calloc()");

   current->plugin.name = strdup(name);
   current->plugin.path = strdup(path);

   current->plugin.enabled = Parser_Activated_Plugin(name);

   current->plugin.handle = dlopen(Plugin_Getfile(name, path), RTLD_NOW);
   if (!current->plugin.handle)
   {
      #ifdef DEBUG
         Debug_msg("Plugin_Load - %s - dlopen() | %s", Plugin_Getfile(name, path), dlerror());
      #endif
      return 0;
   }


#if defined(OPENBSD) || defined(MACOSX)
   current->plugin.fini_function = dlsym(current->plugin.handle, "_Plugin_Fini");
#else
   current->plugin.fini_function = dlsym(current->plugin.handle, "Plugin_Fini");
#endif
   if (current->plugin.fini_function == NULL)
   {
      #ifdef DEBUG
         Debug_msg("Plugin_Load - %s - dlsym() | %s", Plugin_Getfile(name, path), dlerror());
      #endif
      dlclose(current->plugin.handle);
      current->plugin.handle = NULL;
      return 0;
   }

#if defined(OPENBSD) || defined(MACOSX)
   current->plugin.init_function = dlsym(current->plugin.handle, "_Plugin_Init");
#else
   current->plugin.init_function = dlsym(current->plugin.handle, "Plugin_Init");
#endif
   if (current->plugin.init_function == NULL)
   {
      #ifdef DEBUG
         Debug_msg("Plugin_Load - %s - dlsym() | %s", Plugin_Getfile(name, path), dlerror());
      #endif
      dlclose(current->plugin.handle);
      current->plugin.handle = NULL;
      return 0;
   }


   if ((current->plugin.init_function)(current) == 1)   // inizialize the plugin
   {
      LIST_INSERT_HEAD(&loaded_plug_list, current, next);
      return 1;
   }
   else
   {
      dlclose(current->plugin.handle);
      current->plugin.handle = NULL;
      return 0;
   }
}



int Plugin_UnLoad(char *name)
{
   struct plug_list *current;

#ifdef DEBUG
   Debug_msg("Plugin_UnLoad -- unloading %s plugin", name);
#endif

   LIST_FOREACH(current, &loaded_plug_list, next)
   {
      if (!strcmp(current->plugin.name, name))
      {
         (current->plugin.fini_function)(NULL);
         dlclose(current->plugin.handle);
         current->plugin.handle = NULL;
         return 1;
      }
   }
   return 0;
}



void Plugin_SetActivation(char *name, char status)
{
   struct plug_list *current;

#ifdef DEBUG
   Debug_msg("Plugin_SetActivation -- %s\t %d", name, status);
#endif

   LIST_FOREACH(current, &loaded_plug_list, next)
   {
      if (!strcmp(current->plugin.name, name))
      {
         current->plugin.enabled = status;
         return;
      }
   }
}


void Plugin_HookPoint(char hook_point, void *args)
{
   struct plug_list *current;

   LIST_FOREACH(current, &loaded_plug_list, next)
   {
      if (current->plugin.enabled == 1 &&
          current->plugin.ops.hook_point == hook_point)
      {
         (current->plugin.ops.hook_function)(args);
      }
   }
}



int Plugin_RunExt(char *name)
{
   struct plug_list *current;
   int (*Plug_init)(void *);

#ifdef DEBUG
   Debug_msg("Plugin_RunExt -- executing external plugin %s", name);
#endif

   LIST_FOREACH(current, &loaded_plug_list, next)
   {
      if (current->plugin.ops.plug_type == PT_EXT && !strcmp(current->plugin.name, name))
      {
         Plugin_SYS_Output("Starting %s plugin...", name);

         current->plugin.handle = dlopen(Plugin_Getfile(current->plugin.name, current->plugin.path), RTLD_NOW);

         #if defined(OPENBSD) || defined(MACOSX)
            current->plugin.fini_function = dlsym(current->plugin.handle, "_Plugin_Fini");
            Plug_init = dlsym(current->plugin.handle, "_Plugin_Init");
         #else
            current->plugin.fini_function = dlsym(current->plugin.handle, "Plugin_Fini");
            Plug_init = dlsym(current->plugin.handle, "Plugin_Init");
         #endif

         /* error checking was made at Plugin_Load(...) */

         (Plug_init)(current);                        // register the plugin

         (current->plugin.ops.hook_function)(NULL);   // call the hook function

         (current->plugin.fini_function)(NULL);       // clean up

         dlclose(current->plugin.handle);             // unload

         if (!Options.normal)
            Plugin_SYS_Output("%s plugin ended.  (press 'q' to quit...)", name);
         else
            Plugin_SYS_Output("%s plugin ended.", name);

         #ifdef DEBUG
            Debug_msg("Plugin_RunExt -- shutting down external plugin %s", name);
         #endif

         return 1;
      }
   }
   return 0;
}



char * Plugin_Getname(char *file)         // parses  "ec_dummy.so"  and return  "dummy"
{
   static char name[20];

   memset(name, 0, sizeof(name));

   if (!match_pattern(file, "ec_*.so"))
      return NULL;

   strlcpy(name, file+3, sizeof(name));
   name[strlen(name)-3] = 0;

   return name;
}



char * Plugin_Getfile(char *name, char *path)      // parses  "dummy"  and return  "path/ec_dummy.so"
{
   static char file[100];

   snprintf(file, sizeof(file), "%s/ec_%s.so", path, name);
   file[sizeof(file)-1] = 0;

   return file;
}


char ** Plugin_ExtList(void)
{
   struct plug_list *current;
   char ** list;
   char line[100];
   int i = 0;

   list = (char **)calloc(1, sizeof(char *));

   LIST_FOREACH(current, &loaded_plug_list, next)
   {
      if (current->plugin.ops.plug_type == PT_EXT)
      {
         ++i;
         list = (char **)realloc(list, (i+1)*sizeof(char *));
         snprintf(line, sizeof(line), "%2d) %8s     v %.1f -- %s\n", i, current->plugin.name, (float)(current->plugin.ops.plug_version)/10, current->plugin.ops.plug_info);
         list[i-1] = strdup(line);
      }
   }

   list[i] = NULL;

   return list;
}



int Plugin_ExtArray(void)
{
   struct plug_list *current;
   int i = 0;

   LIST_FOREACH(current, &loaded_plug_list, next)
   {
         ++i;
         Plugins_Array = (struct plug_array *)realloc(Plugins_Array, (i+1)*sizeof(struct plug_array));
         Plugins_Array[i-1].name = strdup(current->plugin.name);
         Plugins_Array[i-1].version = (float)current->plugin.ops.plug_version / 10;
         Plugins_Array[i-1].description = strdup(current->plugin.ops.plug_info);
         if (current->plugin.ops.plug_type == PT_EXT)
            Plugins_Array[i-1].status = 'E';
         else if (current->plugin.enabled == 1)
            Plugins_Array[i-1].status = 'A';
         else
            Plugins_Array[i-1].status = ' ';
   }
   return i;
}



// ===== PLUGIN I/O =====

int Plugin_Input(char *string, size_t size, short mode)
{
   int nchars;

   if (mode == P_BLOCK)
      nchars = Plugin_Input_GetChar_Block(string, size);
   else // P_NONBLOCK
      nchars = Plugin_Input_GetChar_NonBlock(string, size);

   return nchars;

}



void Plugin_Output(char *message, ...)
{
   va_list ap;
   char plug_output[501];  // should be enough

   va_start(ap, message);
   vsnprintf(plug_output, 500, message, ap);
   va_end(ap);

#ifdef HAVE_NCURSES
   if (!Options.normal)
   {
      wprintw(plugin_window, "%s", plug_output);
      pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
      doupdate();
   }
   else
#endif
   {
      fprintf(stdout, "%s", plug_output);
      fflush(stdout);
   }
}


void Plugin_SYS_Output(char *message, ...)
{
   va_list ap;
   char plug_output[501];  // should be enough

   va_start(ap, message);
   vsnprintf(plug_output, 500, message, ap);
   va_end(ap);


#ifdef HAVE_NCURSES
   if (!Options.normal)
   {
      #define HELP_COLOR 6
      #define NORM_COLOR 1
      wbkgdset(plugin_window, COLOR_PAIR(HELP_COLOR)); wattron(plugin_window, A_BOLD);
      wprintw(plugin_window, "\n%s\n", plug_output);
      wbkgdset(plugin_window, COLOR_PAIR(NORM_COLOR)); wattroff(plugin_window, A_BOLD);
      pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
      doupdate();
   }
   else
#endif
   {
      fprintf(stdout, "\n\033[36m %s \033[0m\n", plug_output);
      fflush(stdout);
   }

}


void Plugin_Hook_Output(char *message, ...)
{
   va_list ap;
   char plug_output[501];  // should be enough

   va_start(ap, message);
   vsnprintf(plug_output, 500, message, ap);
   va_end(ap);

#ifdef HAVE_NCURSES
   if (!Options.normal)
   {
      int mesglen = strlen(plug_output);
      Buffer_Put(pipe_with_plugins, &mesglen, sizeof(int) );
      Buffer_Put(pipe_with_plugins, plug_output, mesglen );
   }
   else
#endif
   {
      fprintf(stdout, "%s", plug_output);
      fflush(stdout);
   }
}






int Plugin_Input_GetChar_Block(char *string, size_t size)   // the real input
{
   int nchars=0;

   #ifdef HAVE_NCURSES
      if (!Options.normal)
      {
         pnoutrefresh(plugin_window, scroll_yp, 0, W_MAINY1 + 3, 3, W_MAINY2 - 3 , W_MAINX2 - 2);
         doupdate();
      }
   #endif

   memset(string, 0, size);

   loop
   {
      #ifdef HAVE_NCURSES
         if (!Options.normal)
         {
            int c = 0;
            static int p_text = 0;
            static char text[200] = "";

            c = wgetch(main_window);
            if ( c == 8 || c == 263 || c == KEY_BACKSPACE)  // BACKSPACE
            {
               int x=0,y=0;
               getyx(plugin_window, y, x);
               wmove(plugin_window, y, --x);
               pechochar(plugin_window, ' ');
               wmove(plugin_window, y, x);
               text[p_text] = 0;
               if ( p_text > 0 ) p_text--;
            }
            else
            {
               pechochar(plugin_window, c);
               if (p_text < 200) text[p_text++] = c;
            }

            if ( c == '\n')
            {
               strncpy(string, text, size-1);
               memset(text, 0, sizeof(text));
               nchars = p_text;
               p_text = 0;
               string[strlen(string)-1] = 0;  // remove the \n
               break;
            }
         }
         else
      #endif
         {
            read(0, string + nchars, 1);
            if (string[nchars] == 8)
            {
               nchars -= 2;
               string[nchars+1] = 0;
            }
         }

      if (nchars++ >= size || string[nchars-1] == '\n')
         break;
   }

   return nchars;

}


int Plugin_Input_GetChar_NonBlock(char *string, size_t size)   // the real input
{
   int nchars=0;
   fd_set msk_fd;
   struct timeval TimeOut;

   memset(&TimeOut, 0, sizeof(TimeOut));  //  timeout = 0
   FD_ZERO(&msk_fd);

   loop
   {
      FD_SET(0, &msk_fd);

      select(FOPEN_MAX, &msk_fd, (fd_set *) 0, (fd_set *) 0, &TimeOut);

      if (FD_ISSET(0, &msk_fd))
      {
         #ifdef HAVE_NCURSES
            if (!Options.normal)
            {
               int c = 0;
               static int p_text = 0;
               static char text[200] = "";

               c = wgetch(main_window);
               if ( c == 8 || c == 263 || c == KEY_BACKSPACE)  // BACKSPACE
               {
                  int x=0,y=0;
                  getyx(plugin_window, y, x);
                  wmove(plugin_window, y, --x);
                  pechochar(plugin_window, ' ');
                  wmove(plugin_window, y, x);
                  text[p_text] = 0;
                  if ( p_text > 0 ) p_text--;
               }
               else
               {
                  pechochar(plugin_window, c);
                  if (p_text < 200) text[p_text++] = c;
               }

               if ( c == '\n')
               {
                  strncpy(string, text, size-1);
                  memset(text, 0, sizeof(text));
                  nchars = p_text;
                  p_text = 0;
                  string[strlen(string)-1] = 0;  // remove the \n
                  break;
               }
            }
            else
         #endif
            {
               read(0, string + nchars, 1);
               if (string[nchars] == 8)
               {
                  nchars -= 2;
                  string[nchars+1] = 0;
               }
            }

         if (nchars++ >= size || string[nchars-1] == '\n')
            break;
      }
      else                    // no input
          break;
   }

   return nchars;

}



#endif   // PERMIT_PLUGINS

/* EOF */
