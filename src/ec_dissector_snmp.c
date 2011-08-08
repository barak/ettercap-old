/*
    ettercap -- dissector for SNMP (community names) -- UDP 161

    Copyright (C) 2001  ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>

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

    $Id: ec_dissector_snmp.c,v 1.5 2001/12/09 20:24:51 alor Exp $
*/


#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

/* Protocol version numbers */
/* for further implementation
#define SNMP_VERSION_1 0
#define SNMP_VERSION_2c 1
#define SNMP_VERSION_2u 2
#define SNMP_VERSION_3 3

static const value_string versions[] = {
 { SNMP_VERSION_1, "1" },
 { SNMP_VERSION_2c, "2C" },
 { SNMP_VERSION_2u, "2U" },
 { SNMP_VERSION_3, "3" },
 { 0, NULL },
};*/
//------------------------------------

// protos

FUNC_DISSECTOR(Dissector_snmp);
char *com_name(unsigned char *buf);
// --------------------

char *com_name(unsigned char *buf)
{
   unsigned int i=0, ssize=0;
   u_char *name;

   while(buf[i++] != '\x04' && i < 500);

   if(buf[i-1] == '\x04' && buf[i] != '\x00')
   {
      if(buf[i] == 129)
      {
         i++;
         ssize = buf[i];
      }
      else if(buf[i] == 130)
      {
         if(buf[i+1]=='\x01'&&buf[i+2]=='\x00')
         {
            i+=2;
            ssize = 256;
         }
         else
            return NULL;
      }
      else
         ssize = buf[i];

      if (ssize>100) return NULL; // Another little check

      name = (char *)calloc(ssize+5,1);
      memcpy(name, (char *)&buf[i+1], ssize);
      return name;
   }

   return NULL;
}


FUNC_DISSECTOR(Dissector_snmp)
{
   UDP_header *udp;
   u_char *payload;
   u_char *dname;

   udp = (UDP_header *) data;
   payload = (char *) ((int)udp + UDP_HEADER);

#ifdef DEBUG
   Debug_msg("\tDissector_SNMP");
#endif

   if (data_to_ettercap->datalen == 0) return 0; // No data...

   dname = com_name(payload);

   if (dname != NULL)
   {
      sprintf(data_to_ettercap->user, "\n");
      sprintf(data_to_ettercap->pass, "\n");
      snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "COMMUNITY: %s\n", dname);
      free(dname);
   }

   return 0;
}

/* EOF */
