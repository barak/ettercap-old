/*
    ettercap -- dissector for Napster -- TCP 6666 7777 8888

    Copyright (C) 2001 ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>

    Additional Copyright for this file:  LnZ <lnz@iname.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Founcollectoron; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Founcollectoron, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Id: ec_dissector_napster.c,v 1.6 2001/12/13 17:05:20 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

#define CMD_LOGIN     2

typedef struct {
    u_short lenght;     //Lenght of Data
    u_short type;       //Type of Data
} NAPSTER_header;

// protos
FUNC_DISSECTOR(Dissector_napster);

// __________________________

FUNC_DISSECTOR(Dissector_napster)
{
   TCP_header *tcp;
   NAPSTER_header *nap;
   u_char *payload;
   char *collector = NULL;
   u_short len = -1;
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   if (ntohs(tcp->source) == SERV_PORT ) return 0; // skip server messages
   if (data_to_ettercap->datalen == 0) return 0;   // No Data

   payload = (char *)((int)tcp + tcp->doff * 4);
   nap = (NAPSTER_header *) payload;

   if (ptohs(&nap->type) == CMD_LOGIN)
   {
      char *p;

      #ifdef DEBUG
         Debug_msg("\tDissector_napster");
      #endif
      // Format: <nick> <password> <port> "<client-info>" <link-type> [ <num> ]
      len = ptohs(&nap->lenght);

      if (len > data_to_ettercap->datalen) return 0;

      collector = (char *) calloc(len+1, sizeof(char));
      if (!collector)
         ERROR_MSG("calloc()");

      strlcpy(collector, (char *)(nap+1), len+1); //All the login info delimited by spaces

      p = strtok(collector, " ");
      if (p)
      {
         snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", p);
         p = strtok(NULL, " ");
         if (p)
         {
            snprintf(data_to_ettercap->pass, sizeof(data_to_ettercap->pass), "%s\n", p);
            sprintf(data_to_ettercap->type, "Napster");
         }
      }
      free(collector);
   }
   return 0;
}

/* EOF */
