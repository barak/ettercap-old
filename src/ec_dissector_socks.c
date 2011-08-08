/*
    ettercap -- dissector SOCKS5 -- TCP 1080

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

    $Id: ec_dissector_socks.c,v 1.5 2001/12/13 17:05:20 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_socks);

// --------------------


FUNC_DISSECTOR(Dissector_socks)
{

   TCP_header *tcp;
   u_char *payload;
   int len;
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;
   payload = (char *)((int)tcp + tcp->doff * 4);

   if (*payload != 5 ) return 0;    // not the right version (5)

   if ((data_to_ettercap->datalen == 2) && !memcmp(payload, "\x05\x02", 2) && ntohs(tcp->source) == SERV_PORT)   // server accepted user/password method
   {
      #ifdef DEBUG
         Debug_msg("\tDissector_SOCKS 5 -- auth user/pass");
      #endif
      Dissector_StateMachine_SetStatus(data_to_ettercap, 1, NULL);
      return 0;
   }

   if (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == 1 && ntohs(tcp->dest) == SERV_PORT)
   {
      len = *++payload;
      if (len>23) len = 23;      // adapted to fit in our buffer...

      #ifdef DEBUG
         Debug_msg("\tDissector_SOCKS 5 -- USER len %d", len);
      #endif

      strlcpy(data_to_ettercap->user, ++payload, len+1);
      sprintf(data_to_ettercap->user, "\n");

      payload += len;
      len = *payload;
      if (len>23) len = 23;

      #ifdef DEBUG
         Debug_msg("\tDissector_SOCKS 5 -- PASS len %d", len);
      #endif

      strlcpy(data_to_ettercap->pass, ++payload, len+1);
      sprintf(data_to_ettercap->pass, "\n");

      Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);
   }

   return 0;
}


/* EOF */

