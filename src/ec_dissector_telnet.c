/*
    ettercap -- dissector TELNET -- TCP 23

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

    $Id: ec_dissector_telnet.c,v 1.5 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_CTYPE_H
   #include <ctype.h>
#endif

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

#ifndef HAVE_CTYPE_H
   int isprint(int c);
#endif

FUNC_DISSECTOR(Dissector_telnet);

// --------------------

#ifndef HAVE_CTYPE_H
   int isprint(int c)
   {
      return ( (c>31 && c<127) ? 1 : 0 );
   }
#endif

FUNC_DISSECTOR(Dissector_telnet)
{

   TCP_header *tcp;
   u_char *payload;
   char collector[30];
   int datalen;

   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   if (ntohs(tcp->source) == SERV_PORT) return 0;     // skip server messages...
   if (data_to_ettercap->datalen == 0) return 0;      // no data...

   payload = (char *)((int)tcp + tcp->doff * 4);

   memset(collector, 0, sizeof(collector));
   datalen = (data_to_ettercap->datalen > sizeof(collector)) ? sizeof(collector) : data_to_ettercap->datalen;
   strncpy(collector, payload, datalen);

   if (strcmp(collector, ""))
   {
      int i, end=0;

      for (i=0; i<strlen(collector); i++)
      {
         if (collector[i] == '\n' || collector[i] == '\r')
            end = 1;

         if (!isprint((int)collector[i]))
            collector[i] = 0;
      }

      if (strcmp(collector, ""))                      // again on modified collector
      {
         if (end) strcat(collector, "\n");            // this is the terminator char for the data collection (ec_decodata.c)

         strlcpy(data_to_ettercap->user, collector, sizeof(data_to_ettercap->user)-1);
         strlcpy(data_to_ettercap->pass, collector, sizeof(data_to_ettercap->pass)-1);
      }
      else if (end)
      {
         sprintf(data_to_ettercap->user, "\n");
         sprintf(data_to_ettercap->pass, "\n");
      }
   }

   return 0;
}

/* EOF */
