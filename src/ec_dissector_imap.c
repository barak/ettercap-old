/*
    ettercap -- dissector IMAP 4 -- TCP 143 220

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

    $Id: ec_dissector_imap.c,v 1.5 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_imap);

// --------------------


FUNC_DISSECTOR(Dissector_imap)
{

   TCP_header *tcp;
   u_char *payload;
   char *fromhere;
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   if (ntohs(tcp->source) == SERV_PORT) return 0;     // skip server messages...
   if (data_to_ettercap->datalen == 0) return 0;      // no data...

   payload = (char *)((int)tcp + tcp->doff * 4);

   if ( (fromhere = strstr(payload, "LOGIN")) && !strstr(payload, "AUTHENTICATE") )    // plain text login
   {
      char collector[80];
      char *p;

      #ifdef DEBUG
         Debug_msg("\tDissector_IMAP LOGIN ");
      #endif

      strlcpy(collector, fromhere + strlen("LOGIN "), sizeof(collector) );
      p = strtok(collector, " ");
      if (p)
      {
         snprintf(data_to_ettercap->user, 25, "%s\n", p);
         p = strtok(NULL, " ");
         if (p)
            snprintf(data_to_ettercap->pass, 25, "%s\n", p);
         else
            sprintf(data_to_ettercap->pass, "\n");
      }

      return 0;
   }

   switch (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL))
   {
      case 0: // look for authenticate type
               if ( (fromhere = strstr(payload, "AUTHENTICATE")) )
               {
                  char collector[80];

                  #ifdef DEBUG
                     Debug_msg("\tDissector_IMAP %s", payload);
                  #endif

                  strlcpy(collector, fromhere + strlen("AUTHENTICATE "), sizeof(collector) );

                  if (!strncasecmp(collector, "LOGIN", 5))
                  {
                     Dissector_StateMachine_SetStatus(data_to_ettercap, 1, NULL);   // wait for the next packet in which there will be the login (base64)
                  }
                  else if (!strncasecmp(collector, "SKEY", 5))
                  {
                     Dissector_StateMachine_SetStatus(data_to_ettercap, 3, NULL);   // wait for the next packet in which there will be the login (base64)
                  }
                  else
                  {
                     sprintf(data_to_ettercap->user, "\n");
                     sprintf(data_to_ettercap->pass, "\n");
                     snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "Authenticated with %s\n", collector);
                  }
               }
               break;
      case 1: // waiting for user
               {
                  char collector[strlen(payload)];
                  #ifdef DEBUG
                     Debug_msg("\tDissector_IMAP AUTH LOGIN USER");
                  #endif
                  Dissector_base64decode(collector, payload);
                  snprintf(data_to_ettercap->user, 25, "%s\n", collector);
                  Dissector_StateMachine_SetStatus(data_to_ettercap, 2, NULL);
               }
               break;
      case 2: // waiting for pass
               {
                  char collector[strlen(payload)];
                  #ifdef DEBUG
                     Debug_msg("\tDissector_IMAP AUTH LOGIN PASS");
                  #endif
                  Dissector_base64decode(collector, payload);
                  snprintf(data_to_ettercap->pass, 25, "%s\n", collector);
                  snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "Authenticated LOGIN\n");
                  Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);
               }
               break;
      case 3: // auth SKEY we can know only the login... the pass is One-Timed... argh!!
               {
                  char collector[strlen(payload)];
                  #ifdef DEBUG
                     Debug_msg("\tDissector_IMAP AUTH SKEY USER");
                  #endif
                  Dissector_base64decode(collector, payload);
                  snprintf(data_to_ettercap->user, 25, "%s\n", collector);
                  sprintf(data_to_ettercap->pass, "\n");
                  snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "Authenticated with %s\n", collector);
                  Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);
               }
               break;
   }

   return 0;
}


/* EOF */
