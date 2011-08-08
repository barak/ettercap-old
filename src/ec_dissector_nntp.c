/*
    ettercap -- dissector NNTP -- TCP 119

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

    $Id: ec_dissector_nntp.c,v 1.4 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_nntp);

// --------------------


FUNC_DISSECTOR(Dissector_nntp)
{

   TCP_header *tcp;
   u_char *payload;
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   if (ntohs(tcp->source) == SERV_PORT) return 0;     // skip server messages...
   if (data_to_ettercap->datalen == 0) return 0;      // no data...

   payload = (char *)((int)tcp + tcp->doff * 4);

   if ( !strncasecmp(payload, "AUTHINFO USER", 13) )
   {
      #ifdef DEBUG
         Debug_msg("\tDissector_NNTP USER");
      #endif
      snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", payload + 14);
   }

   if ( !strncasecmp(payload, "AUTHINFO PASS", 13) )
   {
      #ifdef DEBUG
         Debug_msg("\tDissector_NNTP PASS");
      #endif
      snprintf(data_to_ettercap->pass, sizeof(data_to_ettercap->pass), "%s\n", payload + 14);
   }

   return 0;
}


/* EOF */
