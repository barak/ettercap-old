/*
    dwarf -- ettercap plugin -- logs all mail activity

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

    $Id: H20_dwarf.c,v 1.1 2001/11/01 14:23:27 alor Exp $
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "../../src/include/ec_main.h"
#include "../../src/include/ec_plugins.h"
#include "../../src/include/ec_error.h"
#include "../../src/include/ec_inet_structures.h"


// protos...

int Plugin_Init(void *);
int Plugin_Fini(void *);
int Parse_Packet(void *data);
void Parse_POP_mail(u_char *data);
void Parse_SMTP_mail(u_char *data);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,
   plug_info:        "logs all mail (POP SMTP) activity",
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

   data_from_ettercap = (DISSECTION *)data;

   if (data_from_ettercap->connection->proto == 'U') return 0;

   if (data_from_ettercap->connection->source_port == 110 || data_from_ettercap->connection->dest_port == 110)
      Parse_POP_mail(data_from_ettercap->layer4);

   if (data_from_ettercap->connection->source_port == 25 || data_from_ettercap->connection->dest_port == 25)
      Parse_SMTP_mail(data_from_ettercap->layer4);


   return 0;
}

/*
 *  FIXME:  this is not concurrent.
 *          it stores all the activity (even from different hosts)
 *          in the same file.
 *          If someone need to have multiple log file, ask us and we
 *          will code it.
 */


void Parse_POP_mail(u_char *data)
{
   FILE *fto;
   static char filename[50] = "";
   time_t tt = time(NULL);
   struct tm *dd = localtime(&tt);
   TCP_header *tcp;
   char *tcp_data;

   if (!strcmp(filename, ""))
      sprintf(filename, "%04d%02d%02d-POP-Activity.log", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday);

   fto = fopen(filename, "a");
   if (fto == NULL)
      ERROR_MSG("fopen()");

   tcp = (TCP_header *)data;

   tcp_data = (char *)((int)tcp + tcp->doff * 4);

   fprintf(fto, "%s", tcp_data);

   fflush(fto);
   fclose(fto);
}


void Parse_SMTP_mail(u_char *data)
{
   FILE *fto;
   static char filename[50] = "";
   time_t tt = time(NULL);
   struct tm *dd = localtime(&tt);
   TCP_header *tcp;
   char *tcp_data;

   if (!strcmp(filename, ""))
      sprintf(filename, "%04d%02d%02d-SMTP-Activity.log", dd->tm_year+1900, dd->tm_mon+1, dd->tm_mday);

   fto = fopen(filename, "a");
   if (fto == NULL)
      ERROR_MSG("fopen()");

   tcp = (TCP_header *)data;

   tcp_data = (char *)((int)tcp + tcp->doff * 4);

   fprintf(fto, "%s", tcp_data);

   fflush(fto);
   fclose(fto);
}


/* EOF */
