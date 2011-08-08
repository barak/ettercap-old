/*
    ettercap -- dissector HTTP Authorization: Basic -- TCP 80 8080

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

    $Id: ec_dissector_http.c,v 1.11 2001/12/13 17:05:20 alor Exp $
*/

#include "include/ec_main.h"

#include <ctype.h>

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"


#define USER 1
#define PASS 2

// protos

FUNC_DISSECTOR(Dissector_http);
int parse_form(char *to_parse, char *ret, char mode);
void decode_url(char *src);

// --------------------------------------

FUNC_DISSECTOR(Dissector_http)
{

   TCP_header *tcp;
   u_char *payload;
   char *fromhere = NULL;
   char collector[MAX_DATA*5];
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   if (ntohs(tcp->source) == SERV_PORT) return 0;     // skip server messages...
   if (data_to_ettercap->datalen == 0) return 0;      // no data...

   payload = (char *)((int)tcp + tcp->doff * 4);

   memset(collector, 0, sizeof(collector));
   memcpy(collector, payload, data_to_ettercap->datalen);

   /*
    *    <FORM> parsing, try to find user and pass form <form> tag
    *
    */

   if (!strncmp(collector, "GET ", 4) && (fromhere = strstr(collector, "?")))
   {
      char *to_parse = NULL;
      char *page = NULL;
      char *host = NULL;
      char *url = NULL;
      char *q;
      char user[25];
      char pass[25];
      size_t len;

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP %d -- method GET -- \n\n%s\n\n", SERV_PORT, collector);
      #endif

      to_parse = strdup(fromhere);
      if ((q = strstr(to_parse, "HTTP")))
         *q = 0;     // get only the parameters...
      else
         return 0;

      if (parse_form(to_parse, user, USER) && parse_form(to_parse, pass, PASS))
      {
         decode_url(user);
         strlcpy(data_to_ettercap->user, user, sizeof(data_to_ettercap->user));
         decode_url(pass);
         strlcpy(data_to_ettercap->pass, pass, sizeof(data_to_ettercap->pass));

         if ((fromhere = strstr(collector, "Referer:")))    // if exist the referer
         {
            url = strdup(fromhere + strlen("Referer: "));
            strtok(url, "\r\n");
            #ifdef DEBUG
               Debug_msg("\tDissector_HTTP -- referer: [%s]", url);
            #endif
         }
         else                                               // get the page from other header
         {
            if ((fromhere = strstr(collector, "GET")))
            {
               page = strdup( fromhere + strlen("GET ") );
               strtok(page, " HTTP");
            }
            else
               page = strdup("/unknown");

            if ((fromhere = strstr(collector, "Host:")))
            {
               host = strdup( fromhere + strlen("Host: ") );
               strtok(host, "\r\n");
            }
            else
               host = strdup("http://unknown");

            len = strlen(page)+strlen(host)+2;
            url = realloc(url, len);
            if (url == NULL)
               ERROR_MSG("realloc()");
            url[len-1]='\0';
            snprintf(url, len, "%s%s", host, page);

            free(page);
            free(host);
            #ifdef DEBUG
               Debug_msg("\tDissector_HTTP -- host + page : [%s]", url);
            #endif
         }

         #ifdef DEBUG
            Debug_msg("\tDissector_HTTP -- after page [%s]", url);
         #endif

         decode_url(url);
         snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "%s\n", url);
         free(url);
      }
      free(to_parse);
      return 0;
   }



   if (!strncmp(collector, "POST ", 5))
   {
      char *to_parse = NULL;
      char *page = NULL;
      char *host = NULL;
      char *url = NULL;
      char user[25];
      char pass[25];
      size_t len;

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP %d -- method POST -- \n\n%s\n\n", SERV_PORT, collector);
      #endif

      if ((fromhere = strstr(collector, "Referer:")))    // if exist the referer
      {
         url = strdup(fromhere + strlen("Referer: "));
         strtok(url, "\r\n");
         #ifdef DEBUG
            Debug_msg("\tDissector_HTTP -- referer: [%s]", url);
         #endif
      }
      else                                               // get the page from other header
      {
         if ((fromhere = strstr(collector, "POST")))
         {
            page = strdup( fromhere + strlen("POST ") );
            strtok(page, " HTTP");
         }
         else page = strdup("/unknown");

         if ((fromhere = strstr(collector, "Host:")))
         {
            host = strdup( fromhere + strlen("Host: ") );
            strtok(host, "\r\n");
         }
         else host = strdup("http://unknown");

         len = strlen(page)+strlen(host)+2;
         url = realloc(url, len);
         if (url == NULL)
           ERROR_MSG("realloc()");
         url[len-1] = '\0';
         snprintf(url, len, "%s%s", host, page);
         free(page);
         free(host);
         #ifdef DEBUG
            Debug_msg("\tDissector_HTTP -- host + page : [%s]", url);
         #endif
      }

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP -- after page [%s]", url);
      #endif

      if (strstr(collector, "User-Agent: Mozilla") && !strstr(collector, "MSIE")
          && !strstr(collector,"Opera"))                                            // if user-agent is Netscape
      {                                                                             // it posts the data in the
         #ifdef DEBUG                                                               // second packet, so we set
            Debug_msg("\tDissector_HTTP -- method POST -- mozilla");                // the state to catch them
         #endif                                                                     // later
         Dissector_StateMachine_SetStatus(data_to_ettercap, 1, NULL);
         decode_url(url);
         snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "%s\n", url);
         free(url);
         return 0;
      }

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP -- after netscape");
      #endif

      if (!strstr(collector, "application/x-www-form-urlencoded"))
         return 0;

      to_parse = strstr(collector, "\r\n\r\n");
      if (to_parse == NULL)
         return 0;
      else
         to_parse += 4;

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP -- after to_parse -- [%s]", to_parse);
      #endif

      if (parse_form(to_parse, user, USER) && parse_form(to_parse, pass, PASS))
      {
         decode_url(user);
         strlcpy(data_to_ettercap->user, user, sizeof(data_to_ettercap->user));
         decode_url(pass);
         strlcpy(data_to_ettercap->pass, pass, sizeof(data_to_ettercap->pass));
         decode_url(url);
         snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "%s\n", url);
         free(url);
      }
      return 0;
   }



   if (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) >= 1)   // Netscape
   {
      char *to_parse;
      char user[25];
      char pass[25];


      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP %d -- mozilla -- second packet", SERV_PORT);
      #endif

      if (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == 1)
      {
         if (!strstr(collector, "Content-type: application/x-www-form-urlencoded"))
         {
            Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);
            return 0;
         }
         Dissector_StateMachine_SetStatus(data_to_ettercap, 2, NULL);
      }

      if ((to_parse = strstr(collector, "\r\n\r\n")))
         to_parse += 4;
      else
         to_parse = collector;

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP - Mozilla - [%s]", to_parse);
      #endif

      if (parse_form(to_parse, user, USER) && parse_form(to_parse, pass, PASS))
      {
         decode_url(user);
         strlcat(data_to_ettercap->user, user, sizeof(data_to_ettercap->user));
         decode_url(pass);
         strlcat(data_to_ettercap->pass, pass, sizeof(data_to_ettercap->pass));
         Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);
      }
      return 0;
   }


   /*
    *    HTTP Authorization
    *
    */

   if ( (fromhere = strstr(collector, "Authorization: Basic")) || (fromhere = strstr(collector, "Proxy-authorization: Basic")) )
   {
      char user[25] = "";
      char pass[25] = "";
      char *decoded;
      char *to_be_decoded;
      char *token;
      char *page = NULL;
      char *host = NULL;

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP -- Authorization -- %s", fromhere);
      #endif

      if (strstr(collector, "GET"))
      {
         page = strdup( strstr(collector, "GET") + strlen("GET ") );
         strtok(page, " HTTP");
         decode_url(page);
      }
      else if (strstr(collector, "POST"))
      {
         page = strdup( strstr(collector, "POST") + strlen("POST ") );
         strtok(page, " HTTP");
         decode_url(page);
      }

      if (strstr(collector, "Host:"))
      {
         host = strdup( strstr(collector, "Host:") + strlen("Host: ") );
         strtok(host, "\r");
         decode_url(host);
      }

      strtok(fromhere, "\r");
      if (!strncmp(fromhere, "Authorization: Basic", 20))
         to_be_decoded = strdup( fromhere+strlen("Authorization: Basic ") );
      else
         to_be_decoded = strdup( fromhere+strlen("Proxy-authorization: Basic ") );

      decoded = strdup(to_be_decoded); // allocate the memory...

      Dissector_base64decode(decoded, to_be_decoded);

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP - decoding - [%s] [%s]", to_be_decoded, decoded);
      #endif

      if ( (token = strsep(&decoded, ":")) != NULL)
      {
         strlcpy(user, token, 20);
         strcat(user, "\n");
         decode_url(user);
         strlcat(data_to_ettercap->user, user, sizeof(data_to_ettercap->user));

         if ( (token = strsep(&decoded, ":")) != NULL)
         {
            strlcpy(pass, token, 20);
            strcat(pass, "\n");
            decode_url(pass);
            strlcat(data_to_ettercap->pass, pass, sizeof(data_to_ettercap->pass));
         }
      }

      snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "http://%s%s\n", host, page);

      #ifdef DEBUG
         Debug_msg("\tDissector_HTTP -- [%s][%s]", host, page);
      #endif

      free(page);
      free(host);
      free(to_be_decoded);
      free(decoded);

      return 0;
   }

   return 0;
}



int parse_form(char *to_parse, char *ret, char mode)
{
   char *user_field[] = {"user", "email", "login", "username", "userid",
                         "form_loginname", "loginname", "pop_login",
                         "uid", "id", "user_id", "screenname", "uname",
                         "ulogin", "acctname", "account", "member",
                         "mailaddress", "membername", "login_username",
                         "uin", ""};

   char *pass_field[] = {"pass", "password", "passwd", "form_pw", "pw",
                         "userpassword", "pwd", "upassword", "login_password", ""};

   char **ptr;
   int i;
   char *tmp = NULL;
   char *var = NULL;
   char *q = tmp;

   decode_url(to_parse);

   if (to_parse[0] == '?') to_parse++;    // strip the '?' from a GET method

   tmp = strdup(to_parse);

   ptr = user_field;
   if (mode == PASS)
      ptr = pass_field;

#ifdef DEBUG
   Debug_msg("\tHTTP_dissector -- parse_form -- [%s]", to_parse);
#endif

   for (i=0; strcmp(ptr[i], ""); i++)
   {
      q = tmp;
      do
      {
         if (*q == '&') q++;
         if (!strncasecmp(q, ptr[i], strlen(ptr[i])) && *(q+strlen(ptr[i])) == '=' )
         {
            if (!strsep(&q, "=") || !(q=strsep(&q, "&")))
            {
               free(tmp);
               return 0;
            }
            var = strdup(q);
            snprintf(ret, 25, "%s\n", var);
            ret[24] = 0;
            free(var);
            free(tmp);
            return 1;
         }
      }
      while ( (q = strchr(q, '&')) );
   }

   free(tmp);
   return 0;
}


void decode_url(char *src)
{
   char t[3];
   int i, j, ch;

   memset(t, 0, sizeof(t));

   for (i = 0, j = 0; src[i] != '\0'; i++, j++)
   {
      ch = src[i];
      if (ch == '%' && isxdigit((int)src[i + 1]) && isxdigit((int)src[i + 2]))
      {
         strlcpy(t, src+i+1, 3);
         ch = strtoul(t, NULL, 16);
         i += 2;
      }
      src[j] = ch;
   }
   src[j] = '\0';
}


/* EOF */
