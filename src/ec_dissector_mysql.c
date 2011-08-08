/*
    ettercap -- dissector MySQL -- TCP 3306

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

    $Id: ec_dissector_mysql.c,v 1.6 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_decodedata.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_mysql);

// --------------------

FUNC_DISSECTOR(Dissector_mysql)
{

   TCP_header *tcp;
   u_char *payload;
   u_char collector[MAX_DATA];
   char seed[9];
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   if (data_to_ettercap->datalen == 0) return 0;      // no data...

   payload = (char *)((int)tcp + tcp->doff * 4);

   memset(collector, 0, MAX_DATA);
   memcpy(collector, payload, data_to_ettercap->datalen);


   if ( (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == 0) && ntohs(tcp->source) == SERV_PORT)            // server messages... collect the random seed
   {
      int i = 5;  // skip first five byte

      if ( memcmp(collector+1, "\x00\x00\x00\x0a\x33\x2e", 6) &&              // magic number... ;) (ver 3.xx.xx)
           memcmp(collector+1, "\x00\x00\x00\x0a\x34\x2e", 6)                 // magic number... ;) (ver 4.xx.xx)
         )
         return 0;

      #ifdef DEBUG
         Debug_msg("\tDissector_MySQL server");
      #endif

      while(collector[i] != collector[i-1] != collector[i-2] != 0)   // search for 000 padding
         i++;
      memset(seed, 0, sizeof(seed));
      strlcpy(seed, collector + i + 1, sizeof(seed));
      snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "Encrypted (one way) seed: %s  pass: ", seed);

      Dissector_StateMachine_SetStatus(data_to_ettercap, 1, NULL);
      return 0;
   }

   if ( (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == 1) && ntohs(tcp->dest) == SERV_PORT)  // client response crypt pass with seed
   {
      char pass[25];

      snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s", collector + 9);
      strlcat(data_to_ettercap->user, "\n", sizeof(data_to_ettercap->user));

      snprintf(pass, sizeof(pass), "%s", collector + 9 + strlen(data_to_ettercap->user) + 1);

      if (strlen(pass) != 0)
         sprintf(data_to_ettercap->pass, "CRYPTED\n");
      else  // NULL password oh yeah !!
         sprintf(data_to_ettercap->pass, "NO PASS yeah ! ;)\n");

      snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "%s\n", pass);
      sprintf(data_to_ettercap->type, "MySQL");

      Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);
    }

    return 0;
}

/* EOF */
