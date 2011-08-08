/*
    ettercap -- dissector IRC -- TCP 6667 6668 6669

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

    $Id: ec_dissector_irc.c,v 1.6 2001/12/12 13:22:58 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"
#include "include/ec_parser.h"

// protos

FUNC_DISSECTOR(Dissector_irc);

// --------------------


FUNC_DISSECTOR(Dissector_irc)
{

   TCP_header *tcp;
   u_char *payload;
   char collector[MAX_DATA];
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   if (ntohs(tcp->source) == SERV_PORT) return 0;      // skip server messages...
   if (data_to_ettercap->datalen == 0) return 0;       // no data...

   payload = (char *)((int)tcp + tcp->doff * 4);

   memset(collector, 0, MAX_DATA);
   memcpy(collector, payload, data_to_ettercap->datalen);

   if ( !strncasecmp(collector, "OPER ", 5) )
   {
      char *usertok;

      #ifdef DEBUG
         Debug_msg("\tDissector_irc OPER");
      #endif

      usertok = strtok(collector + 5, " ");

      if (usertok)
      {
         strlcpy(data_to_ettercap->user, usertok, sizeof(data_to_ettercap->user)-1);
         strlcpy(data_to_ettercap->pass, collector + 5 + strlen(data_to_ettercap->user) + 1, sizeof(data_to_ettercap->pass)-1);
         strlcat(data_to_ettercap->user, "\n", sizeof(data_to_ettercap->user));
         strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
         sprintf(data_to_ettercap->info, "OPER (request for a O-line)\n");
      }
   }

   if ( !strncasecmp(collector, "MODE ", 5) )
   {
      if (strstr(collector + 5, "+k"))
      {
         char *usertok;

         #ifdef DEBUG
            Debug_msg("\tDissector_irc MODE +k");
         #endif

         usertok = strtok(collector + 5, " ");

         if (usertok)
         {
            strlcpy(data_to_ettercap->user, usertok, sizeof(data_to_ettercap->user)-1);
            strlcpy(data_to_ettercap->pass, collector + 5 + strlen(data_to_ettercap->user) + 2, sizeof(data_to_ettercap->pass)-1);
            strlcat(data_to_ettercap->user, "\n", sizeof(data_to_ettercap->user));
            strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
            sprintf(data_to_ettercap->info, "MODE #channel +k password (channel password)\n");
         }
      }
   }

   if ( !strncasecmp(collector, "JOIN ", 5) )
   {
      int i, count = 0;
      char *usertok;

      strtok(collector, "\r");

      for (i=0; i <= strlen(collector); i++) // if count == 2 there is the channel key !
         if (collector[i] == ' ' && (collector[i+1] != 0 && collector[i+1] != '\r')) count++;

      if (count == 2)
      {
         #ifdef DEBUG
            Debug_msg("\tDissector_irc JOIN #chan pass -- [%s]", collector);
         #endif

         usertok = strtok(collector + 5, " ");

         if (usertok)
         {
            strlcpy(data_to_ettercap->user, usertok, sizeof(data_to_ettercap->user)-1);
            strlcpy(data_to_ettercap->pass, collector + 5 + strlen(data_to_ettercap->user) + 1, sizeof(data_to_ettercap->pass)-1);
            strlcat(data_to_ettercap->user, "\n", sizeof(data_to_ettercap->user));
            strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
            sprintf(data_to_ettercap->info, "JOIN #channel password (password channel)\n");
         }
      }
   }


/*
 *    Save a list for nick linked to their IP, we need them for the identification in the
 *    /msg * identify pass
 */

   if ( !strncasecmp(collector, "NICK ", 5) )      // user is changing nickname
   {
      char nick[20];
      strlcpy(nick, collector+5, sizeof(nick));
      strtok(nick, "\r");
      Dissector_StateMachine_SetStatus(data_to_ettercap, 1, nick);
   }

   if ( !strncasecmp(collector, "QUIT ", 5) )      // user has left IRCd
   {
      Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);   // delete the session
   }

   if ( !strncasecmp(collector, "PRIVMSG ", 8) )
   {
      if (match_pattern(collector, "PRIVMSG * :identify *\r\n"))
      {
         char nick[25] = "";
         char *passtok;

         passtok = strstr(collector, "identify");

         if (passtok)
         {
            strlcpy(data_to_ettercap->pass, passtok + strlen("identify") + 1, sizeof(data_to_ettercap->pass)-1);
            strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
            Dissector_StateMachine_GetStatus(data_to_ettercap, nick);
            if (!strcmp(nick, "")) sprintf(nick, "unknown (reg. before)");
            snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", nick);
            snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "/msg %s identify password\n", strtok(collector + 8, " "));
         }
      }
   }

   if ( !strncasecmp(collector, "NICKSERV ", 9) || !strncasecmp(collector, "NS ", 3) )
   {
      if (match_pattern(collector, "*identify *\r\n"))
      {
         char nick[25] = "";
         char *passtok;

         passtok = strstr(collector, "identify");

         if (passtok)
         {
            strlcpy(data_to_ettercap->pass, passtok + strlen("identify") + 1, sizeof(data_to_ettercap->pass)-1);
            strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
            Dissector_StateMachine_GetStatus(data_to_ettercap, nick);
            if (!strcmp(nick, "")) sprintf(nick, "unknown (reg. before)");
            snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", nick);
            snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "/msg %s identify password\n", strtok(collector + 8, " "));
         }
      }
   }

   if ( !strncasecmp(collector, "IDENTIFY ", 9))
   {
      char nick[25] = "";
      char *pass = strstr(collector, " ") + 1;

      if (!pass) return 0;

      if (*pass == ':') pass += 1;

      strlcpy(data_to_ettercap->pass, pass, sizeof(data_to_ettercap->pass)-1);
      strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
      Dissector_StateMachine_GetStatus(data_to_ettercap, nick);
      if (!strcmp(nick, "")) sprintf(nick, "unknown (reg. before)");
      snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", nick);
      snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "/identify password\n");
   }

   return 0;
}


/* EOF */
