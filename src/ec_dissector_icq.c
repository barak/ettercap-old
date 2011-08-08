/*
    ettercap -- dissector for ICQ 2000 v5 -- UDP 4000

    Copyright (C) 2001 ALoR <alor@users.sourceforge.net>, NaGA <crwm@freemail.it>

    Additional Copyright for this file:  LnZ <lnz@iname.com>

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

    $Id: ec_dissector_icq.c,v 1.8 2001/12/20 20:09:45 alor Exp $
*/

#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

#define ICQ_HEADER_LENGTH              0x0018
#define CMD_LOGIN                      0x03E8
#define CMD_LOGIN_OFFSET               0x000E
#define CMD_LOGIN_PASS_LENGHT_OFFSET   0x0008
#define CMD_LOGIN_UIN_OFFSET           0x0006
#define CMD_LOGIN_PASS_OFFSET          0x000A

const u_char table [] = {
   0x59, 0x60, 0x37, 0x6B, 0x65, 0x62, 0x46, 0x48, 0x53, 0x61, 0x4C,
   0x59, 0x60, 0x57, 0x5B, 0x3D, 0x5E, 0x34, 0x6D, 0x36, 0x50, 0x3F,
   0x6F, 0x67, 0x53, 0x61, 0x4C, 0x59, 0x40, 0x47, 0x63, 0x39, 0x50,
   0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x43, 0x69, 0x48, 0x33, 0x31, 0x64,
   0x35, 0x5A, 0x4A, 0x42, 0x56, 0x40, 0x67, 0x53, 0x41, 0x07, 0x6C,
   0x49, 0x58, 0x3B, 0x4D, 0x46, 0x68, 0x43, 0x69, 0x48, 0x33, 0x31,
   0x44, 0x65, 0x62, 0x46, 0x48, 0x53, 0x41, 0x07, 0x6C, 0x69, 0x48,
   0x33, 0x51, 0x54, 0x5D, 0x4E, 0x6C, 0x49, 0x38, 0x4B, 0x55, 0x4A,
   0x62, 0x46, 0x48, 0x33, 0x51, 0x34, 0x6D, 0x36, 0x50, 0x5F, 0x5F,
   0x5F, 0x3F, 0x6F, 0x47, 0x63, 0x59, 0x40, 0x67, 0x33, 0x31, 0x64,
   0x35, 0x5A, 0x6A, 0x52, 0x6E, 0x3C, 0x51, 0x34, 0x6D, 0x36, 0x50,
   0x5F, 0x5F, 0x3F, 0x4F, 0x37, 0x4B, 0x35, 0x5A, 0x4A, 0x62, 0x66,
   0x58, 0x3B, 0x4D, 0x66, 0x58, 0x5B, 0x5D, 0x4E, 0x6C, 0x49, 0x58,
   0x3B, 0x4D, 0x66, 0x58, 0x3B, 0x4D, 0x46, 0x48, 0x53, 0x61, 0x4C,
   0x59, 0x40, 0x67, 0x33, 0x31, 0x64, 0x55, 0x6A, 0x32, 0x3E, 0x44,
   0x45, 0x52, 0x6E, 0x3C, 0x31, 0x64, 0x55, 0x6A, 0x52, 0x4E, 0x6C,
   0x69, 0x48, 0x53, 0x61, 0x4C, 0x39, 0x30, 0x6F, 0x47, 0x63, 0x59,
   0x60, 0x57, 0x5B, 0x3D, 0x3E, 0x64, 0x35, 0x3A, 0x3A, 0x5A, 0x6A,
   0x52, 0x4E, 0x6C, 0x69, 0x48, 0x53, 0x61, 0x6C, 0x49, 0x58, 0x3B,
   0x4D, 0x46, 0x68, 0x63, 0x39, 0x50, 0x5F, 0x5F, 0x3F, 0x6F, 0x67,
   0x53, 0x41, 0x25, 0x41, 0x3C, 0x51, 0x54, 0x3D, 0x5E, 0x54, 0x5D,
   0x4E, 0x4C, 0x39, 0x50, 0x5F, 0x5F, 0x5F, 0x3F, 0x6F, 0x47, 0x43,
   0x69, 0x48, 0x33, 0x51, 0x54, 0x5D, 0x6E, 0x3C, 0x31, 0x64, 0x35,
   0x5A, 0x00, 0x00
};


// protos

FUNC_DISSECTOR(Dissector_icq);
unsigned long get_key(u_char *data, short datalen);
int Decode_icq(u_char *data, short datalen);

// --------------------


unsigned long get_key(u_char *data, short datalen)
{
   u_long A[6] = {0, 0, 0, 0, 0, 0};
   u_long key;
   u_long check;

   check = *(u_long *)(data + 0x14);

   A[1] = check & 0x0001F000;
   A[2] = check & 0x07C007C0;
   A[3] = check & 0x003E0001;
   A[4] = check & 0xF8000000;
   A[5] = check & 0x0000083E;
   A[1] = A[1] >> 0x0C;
   A[2] = A[2] >> 0x01;
   A[3] = A[3] << 0x0A;
   A[4] = A[4] >> 0x10;
   A[5] = A[5] << 0x0F;
   check = A[5] + A[1] + A[2] + A[3] + A[4];
   key = datalen * 0x68656C6C;
   key += check;
   return key;
}

int Decode_icq(u_char *data, short datalen )
{
   unsigned long key,i,k;

   if (datalen <= 0x14 + sizeof(unsigned long)) return 0;// Not enough data to decode
   key = get_key(data, datalen);

   for (i=0x0a; i < datalen+3; i+=4 )
   {
      k = key+table[i&0xff];
      if ( i != 0x16 )
      {
         data[i] ^= (u_char)(k & 0xff);
         data[i+1] ^= (u_char)((k & 0xff00)>>8);
      }
      if ( i != 0x12 ) {
         data[i+2] ^= (u_char)((k & 0xff0000)>>16);
         data[i+3] ^= (u_char)((k & 0xff000000)>>24);
      }
   }
   return 0;
}


FUNC_DISSECTOR(Dissector_icq)
{
   UDP_header *udp;
   u_char *payload;
   char *password = NULL; // ;)
   u_long pwdlen = -1;
   u_char collector[MAX_DATA];
   DATA_DISSECTOR;

   udp = (UDP_header *) data;

   payload = (char *) (int)udp + UDP_HEADER;

   //if (ntohs(udp->source) == SERV_PORT) return 0;  // Skip server messages...
   if (data_to_ettercap->datalen == 0) return 0;   // No data...

   memset(collector, 0, MAX_DATA);
   memcpy(collector, payload, data_to_ettercap->datalen);

   if( ptohs(collector) != 5) return 0;    // Not the right version

#ifdef DEBUG
   Debug_msg("\tDissector_ICQ");
#endif

   Decode_icq(collector, data_to_ettercap->datalen); // decrypting....

   if ( ptohs(collector + CMD_LOGIN_OFFSET) != CMD_LOGIN) return 0; // Not a login packet

   snprintf(data_to_ettercap->user, 25, "%ld (ICQ UIN)\n", ptohl(collector + CMD_LOGIN_UIN_OFFSET));  // the login (UIN)

   #ifdef DEBUG
      Debug_msg("\tDissector_ICQ - LOGIN ");
   #endif

   pwdlen = ptohs(collector + ICQ_HEADER_LENGTH + CMD_LOGIN_PASS_LENGHT_OFFSET);
   if (pwdlen > 28) pwdlen = 28;
   password = (char *) calloc(pwdlen+1, sizeof(char) );

   strlcpy(password,(char *)(collector + ICQ_HEADER_LENGTH + CMD_LOGIN_PASS_OFFSET), pwdlen+1);

   snprintf(data_to_ettercap->pass, sizeof(data_to_ettercap->pass), "%s\n", password);
   sprintf(data_to_ettercap->type, "ICQ");

   free(password);

   #ifdef DEBUG
      Debug_msg("\tDissector_ICQ - PASS ");
   #endif

   if (!Conn_Mode)
   {
      Decode_icq(collector, sniff_data_to_ettercap->datasize); // decrypting....

      memcpy(sniff_data_to_ettercap->data, collector, sniff_data_to_ettercap->datasize);
   }

   return 0;
}

/* EOF */
