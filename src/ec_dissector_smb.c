/*
    ettercap -- dissector SMB (Server Message Block) -- TCP 139

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

    $Id: ec_dissector_smb.c,v 1.6 2001/12/09 20:24:51 alor Exp $
*/

/*
 * INFOS TAKEN FROM L0pht Crack 1.5  by  mudge@l0pht.com and weld@l0pht.com
 *
 * NT Server Challenge Sniffing
 *
 * Here is a description of the challenge that takes place over the network
 * when a client, such as a Windows 95 machine, connects to an NT Server.
 *
 *         [assuming initial setup etc...]
 *
 *            8byte "random" challenge
 *      Client <---------------------- Server
 *      OWF1 = pad Lanman OWF with 5 nulls
 *      OWF2 = pad NT OWF with 5 nulls
 *      resp = E(OWF1, Chal) E(OWF2, Chal)
 *            48byte response (24byte lanman 24byte nt)
 *      Client -----------------------> Server
 *
 * The client takes the OWF ( all 16 bytes of it) and pads with 5 nulls.
 * From this point it des ecb encrypts the, now 21byte, OWF with the
 * 8byte challenge. The resulting 24byte string is sent over to the
 * server who performs the same operations on the OWF stored in it's
 * registry and compares the resulting two 24byte strings. If they
 * match the user used the correct passwd.
 *
 */

#include "include/ec_main.h"

#include <errno.h>

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"

#define LM_PROT 0x0D
#define NT_PROT 0x11
#define PLAIN_TEXT 0

#define PW_OFFSET_NT12   65
#define PWNT_OFFSET_NT12 89
#define SK_OFFSET_NT12   72

#define PWNT_OFFSET_LM2 35
#define PW_OFFSET_LM2   59
#define SK_OFFSET_LM2   64

typedef struct {
   u_char  proto[4];
   u_char  cmd;
   u_char  err[4];
   u_char  flags1;
   u_short flags2;
   u_short pad[6];
   u_short tid, pid, uid, mid;
} SMB_header;

typedef struct {
   u_char  mesg;
   u_char  flags;
   u_short len;
} NetBIOS_header;

// protos

FUNC_DISSECTOR(Dissector_smb);

// --------------------


FUNC_DISSECTOR(Dissector_smb)
{

   TCP_header *tcp;
   u_char *payload;
   SMB_header *smb;
   NetBIOS_header *NetBIOS;
   u_char *ptr;
   ONLY_CONNECTION;

   tcp = (TCP_header *) data;

   payload = (char *)((int)tcp + tcp->doff * 4);
   NetBIOS = (NetBIOS_header *)payload;
   smb = (SMB_header *)(NetBIOS + 1);

   if (memcmp(smb->proto, "\xffSMB", 4) != 0)  return 0;  // it isn't SMBsesssetupX

   ptr = (u_char *)(smb + 1);
   if (smb->cmd == 0x73 && data_to_ettercap->dest_port == SERV_PORT )
   {
      unsigned int pcs[6], pw_offset[2], i, j;

      if ( *ptr == 13 )
      {
         short pwlen, unilen;
         char pass[25] = "";
         char *user;

         ptr += 15;
         pwlen = ptohs(ptr);        // ANSI password len
         ptr += 2;
         unilen = ptohs(ptr);       // UNICODE password len

         memset(pass, 0, sizeof(pass));
         if (pwlen > 24 || unilen > 24) return (0);

         #ifdef DEBUG
            Debug_msg("\tDissector_SMB NT LM 0.12 LEN [%d]-[%d]", pwlen, unilen);
         #endif

         if (pwlen > 0 && Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == PLAIN_TEXT)
            strlcpy(pass, ptr + 12, sizeof(pass)-2);

         user = ptr + 12 + pwlen + unilen;

         if ( strlen(user) == 0 && strlen(pass) == 0) return 0; // skip this...

         if (user[2]==0) // Does anyone uses 2 chars users?
         {               // think it's unicode
            int i=0;
            data_to_ettercap->user[0] = 0;

            for(user++; *user!=0 && i<22 && user[1]==0; user+=2)
            {
               i++;
               strlcat(data_to_ettercap->user, user, sizeof(data_to_ettercap->user)-1);
            }
            strlcat(data_to_ettercap->user, "\n", sizeof(data_to_ettercap->user));
         }
         else
            snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", user);

         strlcat(data_to_ettercap->pass, pass, sizeof(data_to_ettercap->pass)-1);
         if (pass[0] != 0)
            strcat(data_to_ettercap->pass, "\n");  // don't forget it !!   datadecode needs it !!

         #ifdef DEBUG
            Debug_msg("\tDissector_SMB NT LM 0.12 USER & PASS");
         #endif
      }
      else if ( *ptr == 10 )
      {
         int pwlen;
         char pass[25] = "";
         char *user;

         #ifdef DEBUG
            Debug_msg("\tDissector_SMB USER & PASS");
         #endif

         ptr += 15;
         pwlen = ptohs(ptr);     // ANSI password len
         ptr += 2;


         memset(pass, 0, sizeof(pass));
         if (pwlen > 24) return (0);

         if (pwlen > 0 && Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == PLAIN_TEXT)
            strlcpy(pass, ptr + 6, sizeof(pass));

         user = ptr + 6 + pwlen;

         if ( strlen(user) == 0 && strlen(pass) == 0) return 0; // skip this...

         if (user[2]==0) // Does anyone uses 2 chars users?
         {               // think it's unicode
            int i=0;
            data_to_ettercap->user[0]=0;

            for(user++; *user!=0 && i<22 && user[1]==0; user+=2)
            {
               i++;
               strlcat(data_to_ettercap->user, user, sizeof(data_to_ettercap->user)-1);
            }
            strlcat(data_to_ettercap->user, "\n", sizeof(data_to_ettercap->user));
         }
         else
            snprintf(data_to_ettercap->user, sizeof(data_to_ettercap->user), "%s\n", user);

         strlcat(data_to_ettercap->pass, pass, sizeof(data_to_ettercap->pass)-1);
         if (pass[0] != 0)
            strcat(data_to_ettercap->pass, "\n");  // don't forget it !!   datadecode needs it !!

      }

      // NT and LANMAN cyphered authentication
      // in l0pht-crack format

      if (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == NT_PROT)
      {
         pw_offset[0] = PW_OFFSET_NT12;
         pw_offset[1] = PWNT_OFFSET_NT12;
      }
      else if (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == LM_PROT)
      {
         pw_offset[0] = PW_OFFSET_LM2;
         pw_offset[1] = PWNT_OFFSET_LM2;
      }
      else return 0;

      data_to_ettercap->info[0]=0;
      for (i=0; i<2; i++)
      {
         char lmhash[100];
         for (j=0; j<6; j++)
         {
            memcpy (pcs+j, (payload + (pw_offset[i] + j*4)), 4);
            pcs[j]=ntohl(pcs[j]);
         }
         snprintf (lmhash, sizeof(lmhash), "%.8x%.8x%.8x%.8x%.8x%.8x", pcs[0], pcs[1], pcs[2], pcs[3], pcs[4], pcs[5]);

         strlcat (data_to_ettercap->info, lmhash, sizeof(data_to_ettercap->info));
         if (!i) strlcat(data_to_ettercap->info, ":", sizeof(data_to_ettercap->info));
      }
      strlcat (data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
      strlcat (data_to_ettercap->info, "\n", sizeof(data_to_ettercap->info));
      Dissector_StateMachine_SetStatus(data_to_ettercap, 0, NULL);
   }
   else if (smb->cmd == 0x72 && data_to_ettercap->source_port == SERV_PORT)
   {
      unsigned int pcs[3], sk_offset, i;

      #ifdef DEBUG
        Debug_msg("\tDissector_SMB -- HASH [0x%02x] -- PROTECTION [0x%02x]", payload[36], payload[39]);
      #endif

      Dissector_StateMachine_SetStatus(data_to_ettercap, payload[36], NULL);

      if (!(payload[39] & 2))    // ...010 (crypyed)  ...000 (plaintext)
      {
         #ifdef DEBUG
            Debug_msg("\tDissector_SMB -- PLAIN TEXT PASSWORD");
         #endif
         Dissector_StateMachine_SetStatus(data_to_ettercap, PLAIN_TEXT, NULL);
      }

      if (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == LM_PROT) sk_offset = SK_OFFSET_LM2;
      else if (Dissector_StateMachine_GetStatus(data_to_ettercap, NULL) == NT_PROT) sk_offset = SK_OFFSET_NT12;
      else return 0;

      // Session key
      for (i=0; i<3; i++)
      {
          memcpy (pcs+i, (payload + sk_offset + i*4), sizeof (int));
          pcs[i] = ntohl(pcs[i]);
      }
      pcs[0]=(pcs[0]<<8)>>8;
      pcs[2]=((u_long)pcs[2])>>24;
      snprintf(data_to_ettercap->info, sizeof(data_to_ettercap->info), "LC 2.5 FORMAT: \"USER\":3:%.6x%.8x%.2x:",pcs[0],pcs[1],pcs[2]);
   }
   return 0;
}


/* EOF */
