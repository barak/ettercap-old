/*
    ettercap -- dissector X11 -- TCP 6000 6001 6002 6003

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

    $Id: ec_dissector_x11.c,v 1.4 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_x11);

// --------------------


FUNC_DISSECTOR(Dissector_x11)
{

   TCP_header *tcp;
   u_char *payload;
   ONLY_CONNECTION;

   if (data_to_ettercap->datalen == 0) return 0;      // no data...

   tcp = (TCP_header *) data;

   payload = (char *)((int)tcp + tcp->doff * 4);

   payload = strstr(payload+12, "MIT-MAGIC-COOKIE-1");

   if (payload)
   {
      int i;

      #ifdef DEBUG
         Debug_msg("\tDissector_X11");
      #endif
      if (ntohs(tcp->dest) >= SERV_PORT && ntohs(tcp->dest) <= SERV_PORT+4)
         snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "On display :%d\n", ntohs(tcp->dest)-SERV_PORT);
      else
         sprintf(data_to_ettercap->user, "\n");
      sprintf(data_to_ettercap->pass, "\n");
      sprintf(data_to_ettercap->info, "MIT-MAGIC-COOKIE-1 ");
      sprintf(data_to_ettercap->type, "X11");

      for (i = 0; i < 16; i++)
         sprintf(data_to_ettercap->info + (i * 2) + 19, "%.2x", payload[i+20]);

      strlcat(data_to_ettercap->info, "\n", sizeof(data_to_ettercap->info));
   }

   return 0;
}

/* EOF */
