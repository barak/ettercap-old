/*
    ettercap -- dissector for LDAP -- TCP 389

    CCopyright (C) 2001  ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>

    Additional Copyright for this file: LnZ Lorenzo Porro

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
    USA.

    $Id: ec_dissector_ldap.c,v 1.4 2001/12/09 20:24:51 alor Exp $
*/


#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"


//------------------------------------

// protos

FUNC_DISSECTOR(Dissector_ldap);

// --------------------


FUNC_DISSECTOR(Dissector_ldap)
{
   TCP_header *tcp;
   u_char *payload, type, user_len, pass_len;

   tcp = (TCP_header *) data;

   if (data_to_ettercap->datalen == 0) return 0;   // No data...
   if (ntohs(tcp->source) == SERV_PORT) return 0;

#ifdef DEBUG
   Debug_msg("\tDissector_LDAP");
#endif

   payload = (char *) ((int)tcp + tcp->doff * 4);

   type = payload[5];

   user_len = payload[11];
   if (user_len > 25) return 0;

   pass_len = payload[13 + user_len];
   if (pass_len > 25) return 0;

   if (type != 0x60 && type != 0x00) return 0;

   if (user_len == 0)
   {
      sprintf(data_to_ettercap->user, "\n");
      sprintf(data_to_ettercap->pass, "\n");
      sprintf(data_to_ettercap->info, "LDAP: Anonymous bind\n");
      return 0;
   }

   memcpy(data_to_ettercap->user, &payload[12], user_len);
   data_to_ettercap->user[user_len] = '\n';

   memcpy(data_to_ettercap->pass, &payload[12] + user_len + 2, pass_len);
   data_to_ettercap->pass[pass_len] = '\n';

   return 0;
}

/* EOF */
