/*
    ettercap -- data decoding module

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

    $Id: ec_decodedata.c,v 1.18 2001/12/09 20:24:51 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_CTYPE_H
   #include <ctype.h>
#endif

#include "include/ec_inet_structures.h"
#include "include/ec_inet.h"
#include "include/ec_error.h"
#include "include/ec_parser.h"


typedef struct
{
   int port;
   char proto;
   char desc[18];
   struct database *next;
} database;

database *d_list = NULL;

typedef struct
{
   char fingerprint[FINGER_LEN+1];
   char os[60];
   struct os_database *next;
} os_database;

os_database *os_list = NULL;


#define HASH_SIZE 64

struct conn_hash_list {
   u_long ips;
   u_long ipd;
   u_short ps;
   u_short pd;
   char proto;
   int index;
   SLIST_ENTRY (conn_hash_list) next;
};

SLIST_HEAD(, conn_hash_list) conn_hash_array[HASH_SIZE];


pthread_mutex_t passive_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t connection_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef HAVE_CTYPE_H
   int isprint(int c);
#endif
int Decodedata_GetArrayIndex(CONNECTION *data);
void Decodedata_SetArrayIndex(CONNECTION *data, int index);
int Decodedata_MakeConnectionList(CONNECTION *data);
int Decodedata_RefreshConnectionList(void);
void Decodedata_UpdateInfo(CONNECTION *ptr, CONNECTION *data);

int Decodedata_MakePassiveList(PASSIVE_DATA *data);
int Decodedata_FreePassiveList(void);
void Decodedata_UpdatePassiveInfo(PASSIVE_DATA *ptr, PASSIVE_DATA *data);

int Decodedata_GetPassiveOS(char *fingerprint, char *os);

char * Decodedata_GetType(char proto, int port1, int port2);
char * Decodedata_GetAsciiData(char *buffer, int buff_len);
char * Decodedata_GetTextData(char *buffer, int buff_len);
char * Decodedata_GetHexData(char *buffer, int buff_len, short dimX);
char * Decodedata_GetEnhanchedHexData(char *buffer, int buff_len, short cr);
char * Decodedata_TCPFlags(char flags);

void Decodedata_ConvertPassiveToHost(void);
void Decodedata_Passive_SortList(void);
int Decodedata_Compare_Host(PASSIVE_DATA *h1, PASSIVE_DATA *h2);

//--------------------------

#ifndef HAVE_CTYPE_H

   int isprint(int c)
   {
      return ( (c>31 && c<127) ? 1 : 0 );
   }

#endif



int Decodedata_GetArrayIndex(CONNECTION *data)
{
   int hash;
   struct conn_hash_list *current;

   hash = (data->fast_source_ip + data->source_port + data->fast_dest_ip + data->dest_port) % HASH_SIZE;

   SLIST_FOREACH(current, &conn_hash_array[hash], next)
   {
      if ( current->proto == data->proto &&
           ((current->ips == data->fast_source_ip && current->ipd == data->fast_dest_ip   // straight
            && current->ps == data->source_port && current->pd == data->dest_port)
            ||
            (current->ipd == data->fast_source_ip && current->ips == data->fast_dest_ip   // reverse
            && current->pd == data->source_port && current->ps == data->dest_port))
         )
         {
            return current->index;
         }
   }

   return -1;
}



void Decodedata_SetArrayIndex(CONNECTION *data, int index)
{
   int hash;
   struct conn_hash_list *newelem;

   hash = (data->fast_source_ip + data->source_port + data->fast_dest_ip + data->dest_port) % HASH_SIZE;

   newelem = (struct conn_hash_list *) calloc(1, sizeof(struct conn_hash_list));
   if (!newelem)
      ERROR_MSG("calloc()");

   newelem->ips = data->fast_source_ip;
   newelem->ipd = data->fast_dest_ip;
   newelem->ps = data->source_port;
   newelem->pd = data->dest_port;
   newelem->proto = data->proto;
   newelem->index = index;

   SLIST_INSERT_HEAD(&conn_hash_array[hash], newelem, next);

}



int Decodedata_MakeConnectionList(CONNECTION *data)
{
   int index = -1;

   pthread_mutex_lock(&connection_mutex);

   index = Decodedata_GetArrayIndex(data);

   if (index != -1)  // the entry already exist
   {
      if (data->proto == 'T')
      {
         Conn_Between_Hosts[index].source_seq = data->source_seq;
         Conn_Between_Hosts[index].flags = data->flags;
      }

      Decodedata_UpdateInfo(&Conn_Between_Hosts[index], data);

      pthread_mutex_unlock(&connection_mutex);

      return number_of_connections;

   }
   else  // create a new entry
   {
      if (number_of_connections <= 0)
         number_of_connections = 1;
      else
         number_of_connections++;

      #ifdef DEBUG
         Debug_msg("Decodedata_MakeConnectionList - new node ! %d ! %c %s:%d - %s:%d ", number_of_connections,
                   data->proto, data->source_ip, data->source_port, data->dest_ip, data->dest_port);
      #endif

      Conn_Between_Hosts = (CONNECTION *)realloc(Conn_Between_Hosts, number_of_connections*sizeof(CONNECTION));
      if ( Conn_Between_Hosts == NULL )
         ERROR_MSG("realloc()");
      else
         memset(&Conn_Between_Hosts[number_of_connections-1], 0, sizeof(CONNECTION));

      Decodedata_SetArrayIndex(data, number_of_connections-1);    // save connection in the hash table

      memcpy(Conn_Between_Hosts[number_of_connections-1].source_ip, &data->source_ip, sizeof(data->source_ip));
      memcpy(Conn_Between_Hosts[number_of_connections-1].dest_ip, &data->dest_ip, sizeof(data->dest_ip));

      Conn_Between_Hosts[number_of_connections-1].fast_source_ip = data->fast_source_ip;
      Conn_Between_Hosts[number_of_connections-1].fast_dest_ip = data->fast_dest_ip;

      Inet_PutMACinString(Conn_Between_Hosts[number_of_connections-1].source_mac, data->source_mac);
      Inet_PutMACinString(Conn_Between_Hosts[number_of_connections-1].dest_mac, data->dest_mac);

      Conn_Between_Hosts[number_of_connections-1].source_port = data->source_port;
      Conn_Between_Hosts[number_of_connections-1].dest_port = data->dest_port;
      Conn_Between_Hosts[number_of_connections-1].proto = data->proto;

      if (strcmp(data->type, ""))
         strlcpy(Conn_Between_Hosts[number_of_connections-1].type, data->type, sizeof(Conn_Between_Hosts[number_of_connections -1].type));
      else
         strlcpy(Conn_Between_Hosts[number_of_connections-1].type,
                 Decodedata_GetType(Conn_Between_Hosts[number_of_connections-1].proto,
                                    Conn_Between_Hosts[number_of_connections-1].source_port,
                                    Conn_Between_Hosts[number_of_connections-1].dest_port),
                 sizeof(Conn_Between_Hosts[number_of_connections -1].type));

      if (Conn_Between_Hosts[number_of_connections-1].proto == 'T')
      {
         if (!(Conn_Between_Hosts[number_of_connections-1].flags & TH_SYN) &&
              ( data->dest_port == 23 || data->source_port == 23 ||
                data->dest_port == 513 || data->source_port == 513) )
                  Conn_Between_Hosts[number_of_connections-1].user[1] = -1;  // flag for the "waiting for syn" only for telnet and rlogin

         Conn_Between_Hosts[number_of_connections-1].source_seq = data->source_seq;
         Conn_Between_Hosts[number_of_connections-1].dest_seq = data->dest_seq;
         Conn_Between_Hosts[number_of_connections-1].flags = data->flags;

         Decodedata_UpdateInfo(&Conn_Between_Hosts[number_of_connections-1], data);
      }
      else if (Conn_Between_Hosts[number_of_connections-1].proto == 'U')
      {

         sprintf(Conn_Between_Hosts[number_of_connections-1].status,  "  UDP ");

         if (strcmp(data->user, ""))
         {
            strtok(data->user, "\n");
            snprintf(Conn_Between_Hosts[number_of_connections-1].user, 30, "USER: %s", data->user);
         }
         if (strcmp(data->pass, ""))
         {
            strtok(data->pass, "\n");
            snprintf(Conn_Between_Hosts[number_of_connections-1].pass, 30, "PASS: %s", data->pass);
         }
         if (strcmp(data->info, "")) strlcpy(Conn_Between_Hosts[number_of_connections-1].info, data->info, 100);
      }

   }

   pthread_mutex_unlock(&connection_mutex);

   return number_of_connections;

}


void Decodedata_UpdateInfo(CONNECTION *ptr, CONNECTION *data)
{

   if (ptr->proto == 'T')
   {
      if (data->flags & TH_RST)
         sprintf(ptr->status,  "KILLED");
      else if (data->flags & TH_SYN)
         sprintf(ptr->status,  "OPENING");
      else if (data->flags & TH_FIN)
         sprintf(ptr->status,  "CLOSING");
      else if (data->flags & TH_PSH)
         sprintf(ptr->status,  "ACTIVE");
      else if (data->flags & TH_ACK)
      {
         if (!strcmp(ptr->status, "CLOSING"))   // FIN ACK
            sprintf(ptr->status,  "CLOSED");          // ACK
      }
      ptr->timestamp = time(NULL);
   }

   if (strcmp(data->type, ""))
      strlcpy(ptr->type, data->type, sizeof(ptr->type));


   if (ptr->user[1] != -1)    // waiting for syn for some protocols like telnet
   {
      if ( ptr->user[0] == 0 )      // the string is under construction
      {
         strlcpy(ptr->user + 1 + strlen(ptr->user+1), data->user, sizeof(ptr->user)-1 - strlen(ptr->user+1) );
         ptr->user[sizeof(ptr->user)-1] = '\0';
         if (strchr(data->user, '\n')) // the string is ultimated
         {
            char str[sizeof(ptr->user)];

            ptr->user[0] = ' ';
            strtok(ptr->user, "\n");

            if ( data->dest_port == 23 || data->source_port == 23 ||
                 data->dest_port == 513 || data->source_port == 513 )
               data->pass[0] = 0;        // evil workaround for telnet... we assume that pass always come AFTER login

            snprintf(str, sizeof(ptr->user), "USER:%s", ptr->user);
            strlcpy(ptr->user, str, sizeof(ptr->user));
         }
      }
      if ( ptr->user[0] != 0 && ptr->pass[0] == 0 )      // the string is under construction
      {
         strlcpy(ptr->pass + 1 + strlen(ptr->pass+1), data->pass, sizeof(ptr->pass)-1 - strlen(ptr->pass+1) );
         ptr->pass[sizeof(ptr->pass) -1] = '\0';
         if (strchr(data->pass, '\n')) // the string is ultimated
         {
            char str[sizeof(ptr->pass)];

            ptr->pass[0] = ' ';
            strtok(ptr->pass, "\n");

            snprintf(str, sizeof(ptr->pass), "PASS:%s", ptr->pass);
            strlcpy(ptr->pass, str,sizeof(ptr->pass));
         }
      }

      if (strlen(data->info) && !strchr(ptr->info, '\n'))
         strlcat(ptr->info, data->info, sizeof(ptr->info));
   }
   else
   {
      if ( (data->flags & TH_SYN) ||
           ( data->dest_port != 23 && data->source_port != 23 &&
             data->dest_port != 513 && data->source_port != 513) )  // telnet and rlogin are enabled only on syn
               ptr->user[1] = 0;                                    // ok, start collecting user and pass...
   }
}



int Decodedata_RefreshConnectionList(void)
{
   struct conn_hash_list *current;
   int i;

#ifdef DEBUG
   Debug_msg("Decodedata_RefreshConnectionList");
#endif

   pthread_mutex_trylock(&connection_mutex);

   for (i=0; i<HASH_SIZE; i++)
      while(!SLIST_EMPTY(&conn_hash_array[i]))
      {
         current = SLIST_FIRST(&conn_hash_array[i]);
         SLIST_REMOVE_HEAD(&conn_hash_array[i], next);
         free(current);
      }

   if (Conn_Between_Hosts) free(Conn_Between_Hosts);
   Conn_Between_Hosts = NULL;
   number_of_connections = 0;

   pthread_mutex_unlock(&connection_mutex);

   return 0;
}



void Decodedata_UpdatePassiveInfo(PASSIVE_DATA *ptr, PASSIVE_DATA *data)
{

   char OS[60];

   if (!strcmp(ptr->ip, ""))
      strlcpy(ptr->ip, data->ip, sizeof(ptr->ip));

   if (!strcmp(ptr->mac, "") && strcmp(data->type, "NL"))   // no mac for non local hosts
      strlcpy(ptr->mac, data->mac, sizeof(ptr->mac));

   if (!strcmp(ptr->type, ""))
      strlcpy(ptr->type, data->type, sizeof(ptr->type));

   ptr->hop = data->hop;

   if (strcmp(data->fingerprint, ""))
   {
      if (!strcmp(ptr->fingerprint, ""))
         strlcpy(ptr->fingerprint, data->fingerprint, sizeof(ptr->fingerprint));

      if (!strcmp(strrchr(ptr->fingerprint, ':'), ":A") || !strcmp(ptr->os, "") )
      {
         strlcpy(ptr->fingerprint, data->fingerprint, sizeof(ptr->fingerprint));

         #ifdef DEBUG
            Debug_msg("Decodedata_UpdatePassiveInfo -- %15s %25s", data->ip, data->fingerprint);
         #endif

         if (Decodedata_GetPassiveOS(data->fingerprint, OS) == 0)
            strlcpy(ptr->os, OS, sizeof(ptr->os));
         else
         {
            ptr->os[0] = 0;
            strlcpy(ptr->os + 1, OS, 58);
            ptr->os[sizeof(ptr->os)-1] = '\0';
         }
      }
   }

   if (data->port != 0)
   {
      struct open_ports *current, *newelem;

      newelem = (struct open_ports *) calloc(1, sizeof(struct open_ports));
      newelem->port = data->port;

      if (data->proto == 'T')
      {
         if (LIST_EMPTY(&ptr->tcp_ports))
            LIST_INSERT_HEAD(&ptr->tcp_ports, newelem, next);
         else
            LIST_FOREACH(current, &ptr->tcp_ports, next)
            {
               if (current->port == data->port)
               {
                  strlcpy(current->banner, data->banner, sizeof(current->banner));
                  free(newelem);
                  break;
               }
               else if (current->port > data->port)
               {
                  if (current == LIST_FIRST(&ptr->tcp_ports))
                     LIST_INSERT_HEAD(&ptr->tcp_ports, newelem, next);
                  else
                     LIST_INSERT_BEFORE(current, newelem, next);
                  break;
               }
               else if (LIST_NEXT(current, next) == LIST_END(&ptr->tcp_ports))
               {
                  LIST_INSERT_AFTER(current, newelem, next);
                  break;
               }
            }
      }
      else if (data->proto == 'U')
      {
         if (LIST_EMPTY(&ptr->udp_ports))
            LIST_INSERT_HEAD(&ptr->udp_ports, newelem, next);
         else
            LIST_FOREACH(current, &ptr->udp_ports, next)
            {
               if (current->port == data->port)
               {
                  free(newelem);
                  break;
               }
               else if (current->port > data->port)
               {
                  if (current == LIST_FIRST(&ptr->udp_ports))
                     LIST_INSERT_HEAD(&ptr->udp_ports, newelem, next);
                  else
                     LIST_INSERT_BEFORE(current, newelem, next);
                  break;
               }
               else if (LIST_NEXT(current, next) == LIST_END(&ptr->udp_ports))
               {
                  LIST_INSERT_AFTER(current, newelem, next);
                  break;
               }
            }
      }
   }

}



int Decodedata_MakePassiveList(PASSIVE_DATA *data)
{
   int num_conn = 1;
   char found = 0;
   PASSIVE_DATA *ptr;

   pthread_mutex_lock(&passive_mutex);

   if (number_of_passive_hosts != 0)
   {
      for(ptr=Passive_Host; num_conn <= number_of_passive_hosts; ptr++)
      {
         num_conn++;

         if (!strcmp(data->type, "NL") && !strcmp(ptr->mac, data->mac))      // the packet is from the GW...
         {                                                                 // search and mark it
            sprintf(ptr->type, "GW");
            strlcpy(ptr->gwforthis, data->ip, sizeof(ptr->gwforthis));
         }

         if (!strcmp(ptr->ip, data->ip))
         {
            Decodedata_UpdatePassiveInfo(ptr, data);
            found = 1;
            if (strcmp(data->type, "NL"))
            {
               pthread_mutex_unlock(&passive_mutex);
               return number_of_passive_hosts;
            }
         }
      }
   }

   if (!found)
   {
      int j;
      struct open_ports *cur;

      #ifdef DEBUG
         Debug_msg("Decodedata_MakePassiveList - new node ! %d ! %s - %s", num_conn, data->ip, data->fingerprint);
      #endif

      Passive_Host = (PASSIVE_DATA *)realloc(Passive_Host, num_conn*sizeof(PASSIVE_DATA));
      if ( Passive_Host == NULL )
         ERROR_MSG("realloc()");
      else
         memset(&Passive_Host[num_conn-1], 0, sizeof(PASSIVE_DATA));

      for (j=0; j<number_of_passive_hosts; j++)    // do a consistency check on the list because we have realloc'ed it.
      {
         cur = LIST_FIRST(&Passive_Host[j].tcp_ports);
         if (cur)
            cur->next.le_prev = &Passive_Host[j].tcp_ports.lh_first;
         cur = LIST_FIRST(&Passive_Host[j].udp_ports);
         if (cur)
            cur->next.le_prev = &Passive_Host[j].udp_ports.lh_first;
      }

      Decodedata_UpdatePassiveInfo(&Passive_Host[num_conn-1], data);

      number_of_passive_hosts = num_conn;
   }

   pthread_mutex_unlock(&passive_mutex);

   return num_conn;

}


int Decodedata_FreePassiveList(void)
{
   int i;
   struct open_ports *cur;

#ifdef DEBUG
   Debug_msg("Decodedata_FreePassiveList");
#endif

   pthread_mutex_lock(&passive_mutex);

   for(i=0; i<number_of_passive_hosts; i++)
   {
      while (!LIST_EMPTY(&Passive_Host[i].tcp_ports))
      {
         cur = LIST_FIRST(&Passive_Host[i].tcp_ports);
         LIST_REMOVE(cur, next);
         free(cur);
      }
      while (!LIST_EMPTY(&Passive_Host[i].udp_ports))
      {
         cur = LIST_FIRST(&Passive_Host[i].udp_ports);
         LIST_REMOVE(cur, next);
         free(cur);
      }
   }

   if (Passive_Host) free(Passive_Host);
   Passive_Host = NULL;
   number_of_passive_hosts = 0;

   pthread_mutex_unlock(&passive_mutex);

   return 0;
}



char * Decodedata_GetHexData(char *buffer, int buff_len, short dimX)
{
   short octets;

   for(octets = 0; octets < dimX; octets++)
   {
      if ( (octets*3.5 + 12) >= dimX ) break;
   }

   if (octets > 16) octets = 16;
   if (octets % 2 == 1) octets--;

   return Decodedata_GetEnhanchedHexData(buffer, buff_len, octets);

}


char * Decodedata_GetEnhanchedHexData(char *buffer, int buff_len, short cr)
{
   static char *hexdata;
   int i, j, jm;
   int c, dim = 0;

   if (buff_len == 0) return "";

   c = cr*3.5 + 11;
   dim = c;

   for (i = 0; i < buff_len; i++)   // approximately
      if ( i % cr == 0)             // approximately
         dim += c;                  // approximately


   if (hexdata) free(hexdata);
   if ( (hexdata = (char *)calloc(dim, sizeof(char))) == NULL)
      ERROR_MSG("calloc()");

   // adapted from dsniff by Dug Song <dugsong@monkey.org>
   sprintf(hexdata,"\n");
   for (i = 0; i < buff_len; i += cr) {
           sprintf(hexdata, "%s %04x: ", hexdata, i );
           jm = buff_len - i;
           jm = jm > cr ? cr : jm;

           for (j = 0; j < jm; j++) {
                   if ((j % 2) == 1) sprintf(hexdata, "%s%02x ", hexdata, (unsigned char) buffer[i+j]);
                   else sprintf(hexdata, "%s%02x", hexdata, (unsigned char) buffer[i+j]);
           }
           for (; j < cr; j++) {
                   if ((j % 2) == 1) strcat(hexdata, "   ");
                   else strcat(hexdata, "  ");
           }
           strcat(hexdata, " ");

           for (j = 0; j < jm; j++) {
                   c = buffer[i+j];
                   c = isprint(c) ? c : '.';
                   sprintf(hexdata, "%s%c", hexdata, c);
           }
           strcat(hexdata,"\n");
   }

   return hexdata;
}



char * Decodedata_GetAsciiData(char *buffer, int buff_len)
{

   int i = 0;

   if (buff_len == 0) return "";

   for(i = 0; i < buff_len; i++)
   {
      if ( !( isprint((int)buffer[i]) || buffer[i] == '\n' || buffer[i] == '\t') )
         buffer[i] = '.';
   }
   buffer[i] = 0;  // terminate the string

   return buffer;
}


char * Decodedata_GetTextData(char *buffer, int buff_len)
{
   int i = 0;

   if (buff_len == 0) return "";

   while ( i < buff_len )
   {
      if (buffer[i] == 0x1b && buffer[i+1] == 0x5b)      //  \033[   escape sequences
      {
         do
         {
            memmove( buffer + i, buffer + i + 1, buff_len - i - 1 );
            buff_len--;
         } while ( !isalpha((int)buffer[i]) && buff_len > i );

         if ( i < buff_len )
         {
            memmove( buffer + i, buffer + i + 1, buff_len - i - 1 );
            buff_len--;
         }
      }
      else if ( !( isprint((int)buffer[i]) || buffer[i] == '\n' ))
      {
         memmove( buffer + i, buffer + i + 1, buff_len - i - 1 );
         buff_len--;
      }
      else i++;
   }

   buffer[buff_len] = '\000';

   return buffer;
}


char * Decodedata_TCPFlags(char flags)
{
   static char string[8];
   char *p;

   memset(string, 0, sizeof(string));
   p = string;

   if (flags & TH_SYN) *p++ = 'S';
   if (flags & TH_FIN) *p++ = 'F';
   if (flags & TH_RST) *p++ = 'R';
   if (flags & TH_ACK) *p++ = 'A';
   if (flags & TH_PSH) *p++ = 'P';

   return string;

}


char * Decodedata_GetType(char proto, int port1, int port2)
{

   static char type[18];
   database *d_index;

   if (d_list == NULL)  // only the first time
   {
      FILE *f_ser;
      char line[1024], desc[18], stype[4];
      int port;

#ifdef DEBUG
   Debug_msg("Decodedata_GetType - loading from /etc/services");
#endif

      if ( (d_index = (database *)calloc(1,sizeof(database))) == NULL)
         ERROR_MSG("calloc()");

      d_list = d_index;

      if (!(f_ser = fopen ("/etc/services", "r")))
         ERROR_MSG("fopen(\"/etc/services\")");

      while (fgets (line, 1024, f_ser))
      {
         if ((sscanf (line, "%16s%u/%s", desc, &port, stype) == 3) && (!strstr (desc, "#")) )
         {
            if ( (d_index->next = ( struct database *) calloc (1, sizeof(database))) == NULL)
               ERROR_MSG("calloc()");

            d_index->port = port;
            if (strstr (stype, "tcp")) d_index->proto = 'T';
            if (strstr (stype, "udp")) d_index->proto = 'U';

            strlcpy (d_index->desc, desc, sizeof(d_index->desc));

            d_index = (database *) d_index->next;
         }
      }

      fclose (f_ser);
      d_index->next = NULL;
   }

   d_index = d_list;
   for( ; d_index; d_index = (database *)d_index->next)
   {
      if ( d_index->proto == proto && (port1 == d_index->port || port2 == d_index->port) )
      {
         strlcpy(type, d_index->desc, sizeof(type));
         return type;
      }
   }

   return "";
}


int Decodedata_GetPassiveOS(char *fingerprint, char *os)
{

   os_database *os_index;
   int ret = -1;

   if (!strcmp(fingerprint, "")) // no fingerprint, no os...
   {
      strcpy(os, "");
      return 1;
   }

   if (os_list == NULL)  // only the first time
   {
      FILE *f_os;
      char line[1024];
      char *ptr;

      if ( (os_index = (os_database *)calloc(1,sizeof(os_database))) == NULL)
         ERROR_MSG("calloc()");

      os_list = os_index;

      f_os = fopen( "./" OS_FILE, "r");
      if (f_os == NULL)
      {
         f_os = fopen( DATA_PATH "/" OS_FILE, "r");
         if (f_os == NULL)
            Error_msg("\nCan't find " OS_FILE " in ./ or " DATA_PATH);
         else
         {
            #ifdef DEBUG
               Debug_msg("Decodedata_GetPassiveOS - loading from " DATA_PATH "/" OS_FILE);
            #endif
         }
      }
      else
      {
         #ifdef DEBUG
            Debug_msg("Decodedata_GetPassiveOS - loading from ./" OS_FILE);
         #endif
      }

      while (fgets (line, 1024, f_os))
      {
         if ( (ptr = strchr(line, '#')) )
            *ptr = 0;

         if (!strlen(line))   // skip 0 length line
            continue;

         if ( (os_index->next = ( struct os_database *) calloc (1, sizeof(os_database))) == NULL)
            ERROR_MSG("calloc()");

         strlcpy(os_index->fingerprint, line, sizeof(os_index->fingerprint));
         strlcpy(os_index->os,line+FINGER_LEN+1, sizeof(os_index->os));
         os_index->os[strlen(os_index->os)-1] = 0;

         os_index = (os_database *) os_index->next;

      }

      fclose (f_os);
      os_index->next = NULL;
   }

   os_index = os_list;
   for( ; os_index; os_index = (os_database *)os_index->next)
   {
      if ( strcmp(os_index->fingerprint, fingerprint) == 0)
      {
         strcpy(os, os_index->os);
         ret = 0;
         break;
      }
      if ( strcmp(os_index->fingerprint, fingerprint) > 0)  // take the nearest entry (next in the file)
      {
         char win[5];
         char pattern[FINGER_LEN+1];

         strcpy(os, os_index->os);  //save the nearest OLD STYLE

         strlcpy(win, fingerprint, sizeof(win));
         strlcpy(pattern, win, sizeof(pattern));
         strlcat(pattern, ":*:", sizeof(pattern));
         strlcat(pattern, fingerprint + 10, sizeof(pattern));

         while (!strncmp(os_index->fingerprint, win, 4))
         {
            if (match_pattern(os_index->fingerprint, pattern))
            {
               strcpy(os, os_index->os);  //save the nearest NEW STYLE (bypassing the MSS)
            }
            os_index = (os_database *)os_index->next;
         }
         ret = 1;
         break;
      }
   }

   #ifdef DEBUG
      Debug_msg("Decodedata_GetPassiveOS - result: %d %s", ret, os);
   #endif

   return ret;
}




void Decodedata_ConvertPassiveToHost(void)
{
   int num_conn = 1;
   PASSIVE_DATA *ptr;

#ifdef DEBUG
   Debug_msg("Decodedata_ConvertPassiveToHost -- %d", number_of_hosts_in_lan);
#endif

   pthread_mutex_lock(&passive_mutex);

   if (number_of_hosts_in_lan > 1) number_of_hosts_in_lan = 1;

   if (number_of_passive_hosts != 0)
   {
      for(ptr=Passive_Host; num_conn <= number_of_passive_hosts; ptr++)
      {
         num_conn++;

         if (strcmp(ptr->type, "NL") && strcmp(ptr->ip, Host_In_LAN[0].ip)) // don't add Non Local IPs and my ip
         {
            number_of_hosts_in_lan++;
            Host_In_LAN = (HOST *)realloc(Host_In_LAN, number_of_hosts_in_lan*sizeof(HOST));
            if ( Host_In_LAN == NULL )
               ERROR_MSG("realloc()");
            else
               memset(&Host_In_LAN[number_of_hosts_in_lan-1], 0, sizeof(HOST));

            strcpy(Host_In_LAN[number_of_hosts_in_lan-1].ip, ptr->ip);
            strcpy(Host_In_LAN[number_of_hosts_in_lan-1].mac, ptr->mac);
            strcpy(Host_In_LAN[number_of_hosts_in_lan-1].name, "unknown");
         }
      }
   }

   pthread_mutex_unlock(&passive_mutex);

#ifdef DEBUG
   Debug_msg("Decodedata_ConvertPassiveToHost -- %d host(s) converted ", number_of_hosts_in_lan );
#endif
}


int Decodedata_Compare_Host(PASSIVE_DATA *h1, PASSIVE_DATA *h2)
{
   u_long ip1, ip2;

   inet_aton(h1->ip, (struct in_addr *)&ip1);
   inet_aton(h2->ip, (struct in_addr *)&ip2);

   if (ntohl(ip1) < ntohl(ip2))
      return -1;
   else if (ntohl(ip1) == ntohl(ip2))
      return 0;
   else
      return 1;
}


void Decodedata_Passive_SortList(void)
{
   int i;
   struct open_ports *cur;

#ifdef DEBUG
   Debug_msg("Decodedata_Passive_SortList");
#endif

   pthread_mutex_lock(&passive_mutex);

   qsort(Passive_Host, number_of_passive_hosts, sizeof(PASSIVE_DATA), (int (*)(const void *, const void *))Decodedata_Compare_Host);

   for (i=0; i<number_of_passive_hosts; i++)    // do a consistency check on the list
   {
      cur = LIST_FIRST(&Passive_Host[i].tcp_ports);
      if (cur)
         cur->next.le_prev = &Passive_Host[i].tcp_ports.lh_first;
      cur = LIST_FIRST(&Passive_Host[i].udp_ports);
      if (cur)
         cur->next.le_prev = &Passive_Host[i].udp_ports.lh_first;
   }

   pthread_mutex_unlock(&passive_mutex);
}


/* EOF */
