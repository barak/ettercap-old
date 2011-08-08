/*
    ettercap -- dissector VNC -- TCP 5900 5901 5902 5903

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

    $Id: ec_dissector_vnc.c,v 1.4 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_vnc);

// --------------------


FUNC_DISSECTOR(Dissector_vnc)
{

   TCP_header *tcp;
   u_char *payload;
   int major, minor, i;
   ONLY_CONNECTION;

   if (data_to_ettercap->datalen == 0) return 0;      // no data...

   tcp = (TCP_header *) data;

   payload = (char *)((int)tcp + tcp->doff * 4);

   if ( (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == 0) && sscanf(payload, "RFB %03d.%03d\n", &major, &minor) )
   {
      #ifdef DEBUG
         Debug_msg("\tDissector_VNC %d %d", major, minor);
      #endif
      Dissector_StateMachine_SetStatus(data_to_ettercap, 1, NULL);
      return 0;
   }

   if ( (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == 1) &&
         ntohs(tcp->source) >= SERV_PORT && ntohs(tcp->source) <= SERV_PORT+4 ) // this is the challenge from the server
   {
      snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "On display :%d\n", ntohs(tcp->source)-SERV_PORT);

      if (!memcmp(payload, "\x00\x01", 4))   // no auth  ;)
      {
         sprintf(data_to_ettercap->pass, "no pass required ;)\n");
         sprintf(data_to_ettercap->type, "VNC");
         Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);  // finished
      }

      if (!memcmp(payload, "\x00\x02", 4))   // auth required
      {
         sprintf(data_to_ettercap->info, "Server Challenge: ");
         for (i = 0; i < 16; i++)
            snprintf(data_to_ettercap->info + (i * 2) + 18, sizeof(data_to_ettercap->info), "%.2x", payload[i+4]);
         Dissector_StateMachine_SetStatus(data_to_ettercap, 2, NULL);
         return 0;
      }
   }

   if (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == 2)   // this is the client 3DES encripted response
   {
      sprintf(data_to_ettercap->pass, "\n");
      sprintf(data_to_ettercap->info, " Client 3DES: ");
      for (i = 0; i < 16; i++)
         snprintf(data_to_ettercap->info + (i * 2) + 16, sizeof(data_to_ettercap->info), "%.2x", payload[i]);

      strcat(data_to_ettercap->info, "\n");
      sprintf(data_to_ettercap->type, "VNC");
      Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);  // finished
   }

   return 0;
}

/* EOF */
