/*
    ettercap -- dissector RIP (Routing Information Protocol) -- UDP 520

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

    $Id: ec_dissector_rip.c,v 1.3 2001/12/06 17:53:01 alor Exp $
*/

/*
 *       RIP version 2      RFC 2453
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    0  | command (1)   | version (1)   |      must be zero (2)         |
 *       +---------------+---------------+-------------------------------+
 *    4  | Address Family Identifier (2) |        Route Tag (2)          |
 *       +-------------------------------+-------------------------------+
 *    8  |                         IP Address (4)                        |
 *       +---------------------------------------------------------------+
 *   12  |                         Subnet Mask (4)                       |
 *       +---------------------------------------------------------------+
 *   16  |                         Next Hop (4)                          |
 *       +---------------------------------------------------------------+
 *   20  |                         Metric (4)                            |
 *       +---------------------------------------------------------------+
 *
 *
 *        0                   1                   2                   3 3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    0  | Command (1)   | Version (1)   |            unused             |
 *       +---------------+---------------+-------------------------------+
 *    4  |             0xFFFF            |    Authentication Type (2)    |
 *       +-------------------------------+-------------------------------+
 *    8  ~                       Authentication (16)                     ~
 *       +---------------------------------------------------------------+
 *
 */

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_rip);

// --------------------


FUNC_DISSECTOR(Dissector_rip)
{

   UDP_header *udp;
   u_char *payload;
   char version;
   ONLY_CONNECTION;

   udp = (UDP_header *) data;

   payload = (char *) (int)udp + UDP_HEADER;

   if (data_to_ettercap->datalen == 0) return 0;   // No data...

   version = payload[1];

   switch(version)
   {
      case 2:
               if ( !memcmp(payload + 4, "\xff\xff\x00\x02", 4) )    //address family 0xFF  Tag 2  (AUTH)
               {
                  #ifdef DEBUG
                     Debug_msg("\tDissector_RIP version 2 simple AUTH");
                  #endif
                  sprintf(data_to_ettercap->user, "RIP version 2\n");
                  strlcpy(data_to_ettercap->pass, payload+8, sizeof(data_to_ettercap->pass)-1);
                  strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
               }
               break;
      case 4:           // TODO RIP v4
               break;
   }


   return 0;
}

/* EOF */
