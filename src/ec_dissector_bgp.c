/*
    ettercap -- dissector BGP 4 (Border Gateway Protocol) -- TCP 179

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

    $Id: ec_dissector_bgp.c,v 1.7 2001/12/20 20:09:45 alor Exp $
*/

/*
 *
 *       BPG version 4     RFC 1771
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    0  |                                                               |
 *       +                                                               +
 *    4  |                                                               |
 *       +                             Marker                            +
 *    8  |                                                               |
 *       +                                                               +
 *   12  |                                                               |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   16  |          Length               |      Type     |    Version    |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   20  |     My Autonomous System      |           Hold Time           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   24  |                         BGP Identifier                        |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   28  | Opt Parm Len  |                                               |
 *       +-+-+-+-+-+-+-+-+       Optional Parameters                     |
 *   32  |                                                               |
 *       |                                                               |
 *       ~                                                               ~
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *        0                   1
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
 *       |  Parm. Type   | Parm. Length  |  Parameter Value (variable)
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...
 *
 *
 *         a) Authentication Information (Parameter Type 1):
 *
 *            This optional parameter may be used to authenticate a BGP
 *            peer. The Parameter Value field contains a 1-octet
 *            Authentication Code followed by a variable length
 *            Authentication Data.
 *
 *                 0 1 2 3 4 5 6 7 8
 *                +-+-+-+-+-+-+-+-+
 *                |  Auth. Code   |
 *                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                |                                                     |
 *                |              Authentication Data                    |
 *                |                                                     |
 *                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *               Authentication Code:
 *
 *                  This 1-octet unsigned integer indicates the
 *                  authentication mechanism being used.  Whenever an
 *                  authentication mechanism is specified for use within
 *                  BGP, three things must be included in the
 *                  specification:
 *
 *                  - the value of the Authentication Code which indicates
 *                  use of the mechanism,
 *                  - the form and meaning of the Authentication Data, and
 *                  - the algorithm for computing values of Marker fields.
 *
 *                  Note that a separate authentication mechanism may be
 *                  used in establishing the transport level connection.
 *
 *               Authentication Data:
 *
 *                  The form and meaning of this field is a variable-
 *                  length field depend on the Authentication Code.
 *
 */


#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

// protos

FUNC_DISSECTOR(Dissector_bgp);

// --------------------


FUNC_DISSECTOR(Dissector_bgp)
{

   TCP_header *tcp;
   u_char *payload;
   u_char *parameters;
   char param_length;
   int i;
   u_char BGP_MARKER[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
   ONLY_CONNECTION;

   if (data_to_ettercap->datalen == 0) return 0;      // No data...

   tcp = (TCP_header *) data;

   payload = (char *)((int)tcp + tcp->doff * 4);

   if ( payload[19] != 4 ) return 0;                  // not the right version (4)

   if ( payload[18] != 1 ) return 0;                  // not a OPEN message

   if ( memcmp(payload, BGP_MARKER, 16) ) return 0;   // BGP marker has to be FFFFFF...

   if ( (param_length = payload[28]) == 0 ) return 0; // no optional parameter

   parameters = payload + 29;

#ifdef DEBUG
   Debug_msg("\tDissector_BGP");
#endif

   for ( i = 0; i <= param_length; i += parameters[i+1]+2 ) // move through the param list
   {
      if (parameters[i] == 1)    // the parameter is an authentication type (1)
      {
         short len = parameters[i+1];
         #ifdef DEBUG
            Debug_msg("\tDissector_BGP version 4 AUTH");
         #endif
         sprintf(data_to_ettercap->user, "\n");
         snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "AUTH TYPE 0x%02x\n", parameters[i+2]);
         strlcpy(data_to_ettercap->pass, parameters + i + 3, (len>28) ? 28 : (len+1));
         strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
         return 0;
      }
   }

   return 0;
}

/* EOF */
