/*
    ettercap -- dissector Half-Life RCON -- UDP 27015

    Copyright (C) 2001  ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>

    Additional Copyright for this file (C) 2001  g3gg0 (geggo@g3gg0.dyndns.org)

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

   format of an rcon-command:

       0xFF 0xFF 0xFF 0xFF "RCON authkey(?) command"

    v0.1  - 02.10.01    initial release
    v0.2  - 03.10.01    small code cleanup
    v0.3  - 05.10.01    now correctly reads out the pass

*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_hl_rcon);

// --------------------


FUNC_DISSECTOR(Dissector_hl_rcon)
{
   int pos = 5;
   int len = 0;
   int datalen = data_to_ettercap->datalen - 1 - UDP_HEADER;
   UDP_header *udp;
   u_char *payload;
   ONLY_CONNECTION;

   if (data_to_ettercap->datalen < 10) return 0;   // No data...

   udp = (UDP_header *) data;
   payload = (char *) (int)udp + UDP_HEADER + 4;   // 1st 4 bytes dont matter

   if ( !strncasecmp(payload, "rcon", 4)  )
   {
      #ifdef DEBUG
         Debug_msg("\tDissector_hl_rcon got RCON command");
      #endif
      while (pos < datalen && payload[pos] != ' ')
         pos++;  //find the whitespace after authkey

      pos++;     // dont want the whitespace...

      while (pos + len < datalen && payload[pos+len] != ' ' && len < 28)
         len++;  // find the next whithespace

      sprintf(data_to_ettercap->user, "Half-Life RCON\n");

      strlcpy(data_to_ettercap->pass, payload + pos, len+1);  // we are sure that len is less then 28 bytes
      strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));

      len = data_to_ettercap->datalen - 4;
      sprintf(data_to_ettercap->info, " - Command: ");
      strlcat(data_to_ettercap->info, payload, (len>135) ? 135 : len+1);
      strlcat(data_to_ettercap->info, "\n", sizeof(data_to_ettercap->info));

      return 0;
   }

   return 0;
}

/* EOF */
