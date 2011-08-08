/*
    ettercap -- thread handling

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

    $Id: ec_threads.c,v 1.4 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_error.h"
#include "include/ec_queue.h"


struct thread_list {
   char name[10];
   pthread_t id;
   LIST_ENTRY (thread_list) next;
};

// global data

LIST_HEAD(, thread_list) thread_list_head;

// protos...

char * ECThread_getname(pthread_t id);
void ECThread_register(pthread_t id, char * name);
pthread_t ECThread_create(char * name, void *(*function)(void *), void *args);
void ECThread_destroy(pthread_t id);

// ----------------------------


char * ECThread_getname(pthread_t id)
{
   struct thread_list *current;

   LIST_FOREACH(current, &thread_list_head, next)
   {
      if (current->id == id)
         return current->name;
   }

   return "NR_THREAD";
}


void ECThread_register(pthread_t id, char * name)
{
   struct thread_list *current, *newelem;

#ifdef DEBUG
   Debug_msg("ECThread_register -- %s", name);
#endif

   newelem = (struct thread_list *) calloc(1, sizeof(struct thread_list));
   if (!newelem)
      ERROR_MSG("calloc()");

   newelem->id = id;
   strlcpy(newelem->name, name, 10);

   LIST_FOREACH(current, &thread_list_head, next)
   {
      if (current->id == id)
      {
         LIST_REPLACE(current, newelem, next);
         return;
      }
   }

   LIST_INSERT_HEAD(&thread_list_head, newelem, next);
}


pthread_t ECThread_create(char * name, void *(*function)(void *), void *args)
{
   pthread_t id;

#ifdef DEBUG
   Debug_msg("ECThread_create -- %s", name);
#endif

   pthread_create(&id, NULL, function, args);

   ECThread_register(id, name);

   return id;
}


void ECThread_destroy(pthread_t id)
{
   struct thread_list *current;

#ifdef DEBUG
   Debug_msg("ECThread_destroy -- terminating %d", id);
#endif

   pthread_cancel(id);

#if !defined(MACOSX) && !defined(CYGWIN)
   /*
    *    Mac OS X (darwin 1.3) and the CYGWIN pthreads implementation
    *    don't support joinable thread
    *    here is only a workaround, because we actually have to
    *    wait for the cancellation function (for example rearp in
    *    doppleganger)
    *
    *    XXX - FIXME:  urgency high !!
    */

   pthread_join(id, NULL);

#endif

   LIST_FOREACH(current, &thread_list_head, next)
   {
      if (current->id == id)
      {
         #ifdef DEBUG
            Debug_msg("ECThread_destroy -- %d [%s] terminated !", current->id, current->name);
         #endif
         LIST_REMOVE(current, next);
         free(current);
      }
   }

}

/* EOF */

