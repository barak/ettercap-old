/*
    ettercap -- dissector PCAnywhere -- TCP 65301

    TOTALLY UNTESTED!!!!!!!!!!!!!!!!!!!!!!

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

    $Id: ec_dissector_pcanywhere.c,v 1.5 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#include <errno.h>

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR (Dissector_pcanywhere);

// --------------------


FUNC_DISSECTOR (Dissector_pcanywhere)
{

   TCP_header *tcp;
   u_char *payload;
   u_char *ptr;
   u_char *endbuf;
   int datalen;
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   if (ntohs(tcp->source) == SERV_PORT) return 0;     // skip server messages...
   if (data_to_ettercap->datalen == 0) return 0;      // no data...

   payload = (char *)((int)tcp + tcp->doff * 4);

   datalen = data_to_ettercap->datalen;
   endbuf = payload + datalen;

   for(ptr = payload; (*ptr) == 0; ptr++); // skip zero padding

   // Test version
   if ((*ptr)<0x0f && (*ptr)!=0x06) // Clear Text
   {
      char buffer[1000];
      int  offset;

      for(;(*ptr)!=0x06 && (u_long)ptr < (u_long)endbuf; ptr++)
      {
         for(offset = 0; (*ptr)!=13 && offset<1000; ptr++) // search for \r
         {
             buffer[offset]=(*ptr);
             offset++;
         }

         if (offset == 1000) return 0;

         buffer[offset] = 0;
      }
      snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", buffer);

      return 0;
   }
   else // Encrypted Text
   {
      for(;;)
      {
         for(;(*ptr)!=0x06; ptr++)
            if ((u_long)ptr >= (u_long)endbuf) return 0;

         ptr++;
         if ((*ptr)==0xff && (u_long)(endbuf-ptr)>1)
         {
            char buffer[1000];
            int i;

            // Is it right?
            ptr+=2;

            if (*ptr>1000) return 0;

            memcpy(buffer, ptr+1, (*ptr));

            for (i=(*ptr)-1; i>0; i--)
                buffer[i] = buffer[i-1] ^ buffer[i] ^ (i-1);

            buffer[0] ^= 0xab;
            snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", buffer);

            return 0;
         }
      }
   }
}

/* EOF */
