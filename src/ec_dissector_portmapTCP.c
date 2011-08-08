/*
    ettercap -- dissector portmap

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

    $Id: ec_dissector_portmapTCP.c,v 1.3 2001/11/19 09:30:22 alor Exp $
*/


#include "include/ec_main.h"

#include "include/ec_dissector.h"
#include "include/ec_inet_structures.h"

//#define MAP_LEN 20
#define XID 0
#define PROG 1
#define PROTO 2
#define VER 3

#define XID_LEN 1024
#define DUMP 1
#define MAP_LEN 20

extern RPC_DISSECTOR Available_RPC_Dissectors[];

int Programs[XID_LEN][4];

FUNC_DISSECTOR(Dissector_portmapTCP);
void RPC_PortInsert( RPC_DISSECTOR *Entry, short port);

void RPC_PortInsert( RPC_DISSECTOR *Entry, short port)
{
   RPC_PORTS **to_enter;

   to_enter = &Entry->ports;
   // He ya...another funny list!!!!!
   if (Entry->ports == NULL)
      Entry->ports = (RPC_PORTS *)malloc (sizeof(RPC_PORTS));
   else
   {
      while(*to_enter != NULL)
      {
         if ((*to_enter)->port == port) return;
         to_enter = (RPC_PORTS **)&((*to_enter)->next);
      }
      *to_enter = (RPC_PORTS *)malloc (sizeof(RPC_PORTS));
   }

   (*to_enter)->port = port;
   (*to_enter)->next = NULL;
}

FUNC_DISSECTOR(Dissector_portmapTCP)
{
   TCP_header *tcp;
   u_char *buf;
   int type,xid,proc,proto,program,version,port,state,len,offs,i,j;

   tcp = (TCP_header *) data;
   buf = (char *)((int)tcp + tcp->doff * 4);

   xid  = *(int *)(buf+4);
   proc = *(int *)(buf+24);
   type = *(int *)(buf+8);
   if ((len=data_to_ettercap->datalen)==0) return (0);

   // CALL
   if (ntohs(tcp->dest) == SERV_PORT)
   {
      proto = *(int *)(buf+52);
      program = *(int *)(buf+44);
      version = *(int *)(buf+48);

      if (type!=0) return (0);

      for (i=0; i<XID_LEN; i++)
         if (!Programs[i][XID]) break;

      if (i==XID_LEN) return (0);

      if (ntohl(proc)==3) // GETPORT
      {
         Programs[i][XID] = xid;
         Programs[i][PROTO] = proto;
         Programs[i][PROG] = program;
         Programs[i][VER] = version;
      }

      if (ntohl(proc)==4) //DUMP
      {
         Programs[i][XID]=xid;
         Programs[i][PROG]=DUMP;
      }

      return (0);
   }

   // REPLY
   for (j=0; j<XID_LEN; j++)
      if (Programs[j][XID] == xid) break;

   if (j == XID_LEN) return (0);

   Programs[j][XID] = 0;
   state = *(int *)(buf+12);

   if (state != 0 || ntohl(type) != 1) // Unsuccess or not a reply :(
      return (0);

   if (Programs[j][PROG]!=DUMP)  // GETPORT Reply
   {
      port = *(int *)(buf+28);
      i = 0;

      while ( Available_RPC_Dissectors[i].program != 0 )
      {
         if ( Available_RPC_Dissectors[i].program == ntohl(Programs[j][PROG]) &&
              Available_RPC_Dissectors[i].version == ntohl(Programs[j][VER]) &&
              Available_RPC_Dissectors[i].proto  == (short)ntohl(Programs[j][PROTO]))
         {
            RPC_PortInsert( &Available_RPC_Dissectors[i], (short)(ntohl(port)) );
            break;
         }
         i++;
      }
   }
   else           // DUMP Reply
   {
      offs = 28;
      while ( (len-offs)>=MAP_LEN )
      {
         program = *(int *)(buf+offs+4);
         version = *(int *)(buf+offs+8);
         proto   = *(int *)(buf+offs+12);
         port    = *(int *)(buf+offs+16);

         i = 0;
         while ( Available_RPC_Dissectors[i].program != 0 )
         {
            if ( Available_RPC_Dissectors[i].program == ntohl(program) &&
                 Available_RPC_Dissectors[i].version == ntohl(version) &&
                 Available_RPC_Dissectors[i].proto  == (short)ntohl(proto))
            {
               RPC_PortInsert( &Available_RPC_Dissectors[i], (short)(ntohl(port)) );
               break;
            }
            i++;
         }
         offs += MAP_LEN;
       }
   }
   return(0);
}
