/*
    ettercap -- Grell -- HTTPS dissector

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

    $Id: ec_grell.c,v 1.10 2001/12/12 13:22:58 alor Exp $
*/

#include "include/ec_main.h"

#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)  // don't compile if you don't have OpenSSL

#include <fcntl.h>

#include <openssl/ssl.h>

#include "include/ec_inet_structures.h"
#include "include/ec_inet_forge.h"
#include "include/ec_dissector.h"
#include "include/ec_buffer.h"
#include "include/ec_error.h"
#include "include/ec_decodedata.h"
#include "include/ec_thread.h"

int Grell_ProxyIP = 0;
int Grell_ProxyPort = 8080;
int proxy_fd, https_fd;

typedef struct
{
    unsigned int    ServerIP;
    unsigned short  ServerPort;
    int             client_fd, server_fd, ssl_type;
    struct          sockaddr_in client_sin, server_sin;
    SSL_CTX         *ssl_ctx_client, *ssl_ctx_server;
    SSL             *ssl_client, *ssl_server;
} public_data;

public_data father_data;

pthread_mutex_t father_mutex = PTHREAD_MUTEX_INITIALIZER;

// protos...

void Grell_Dissector(char *payload, CONNECTION *data_to_ettercap);
void Grell_init(void);
void Grell_fini(void *dummy);
void * Grell_spawn(void *local_father_data);
void * Grell_start(void *);
pthread_t Grell_Run(void);

// ================================

void Grell_Dissector(char *payload, CONNECTION *data_to_ettercap)
{
   char *buf;

   buf = Inet_Forge_packet(MAX_DATA+data_to_ettercap->datalen );                         // prepare the packet for the HTTP dissector
   Inet_Forge_tcp( buf, data_to_ettercap->source_port,      // create a fake tcp header
                        data_to_ettercap->dest_port,
                        0xabadc0de,
                        0xabadc0de,
                        0,
                        payload,
                        data_to_ettercap->datalen);

   Dissector_http(buf, data_to_ettercap, NULL, 1, 443);

   Inet_Forge_packet_destroy( buf );

}

static void client_parse(char *buf, int len, public_data *son_data)
{
   CONNECTION data_to_ettercap;
   SNIFFED_DATA sniff_data_to_ettercap;
   struct in_addr dest;

   memset(&data_to_ettercap, 0, sizeof(CONNECTION));
   memset(&sniff_data_to_ettercap, 0, sizeof(SNIFFED_DATA));

   dest.s_addr = son_data->ServerIP;

   strncpy(data_to_ettercap.source_ip, inet_ntoa(son_data->client_sin.sin_addr), sizeof(data_to_ettercap.source_ip)-1);
   data_to_ettercap.source_ip[sizeof(data_to_ettercap.source_ip)-1]='\0';
   strncpy(data_to_ettercap.dest_ip, inet_ntoa(dest), sizeof(data_to_ettercap.dest_ip)-1);
   data_to_ettercap.dest_ip[sizeof(data_to_ettercap.dest_ip)-1]='\0';

   data_to_ettercap.source_port = ntohs(son_data->client_sin.sin_port);
   data_to_ettercap.dest_port = ntohs(son_data->ServerPort);
   data_to_ettercap.source_seq = 0;
   data_to_ettercap.dest_seq = 0;
   data_to_ettercap.flags = 0;
   data_to_ettercap.proto = 'T';
   data_to_ettercap.datalen = len;
   Grell_Dissector(buf, &data_to_ettercap);

   Decodedata_MakeConnectionList(&data_to_ettercap);

   if (!Connection_Mode)
   {
      strncpy(sniff_data_to_ettercap.source_ip, inet_ntoa(son_data->client_sin.sin_addr), sizeof(sniff_data_to_ettercap.source_ip)-1);
      sniff_data_to_ettercap.source_ip[sizeof(sniff_data_to_ettercap.source_ip)-1]='\0';
      strncpy(sniff_data_to_ettercap.dest_ip, inet_ntoa(dest), sizeof(sniff_data_to_ettercap.dest_ip)-1);
      sniff_data_to_ettercap.dest_ip[sizeof(sniff_data_to_ettercap.dest_ip)-1]='\0';

      sniff_data_to_ettercap.source_port = ntohs(son_data->client_sin.sin_port);
      sniff_data_to_ettercap.dest_port = ntohs(son_data->ServerPort);
      sniff_data_to_ettercap.seq = 0;
      sniff_data_to_ettercap.ack_seq = 0;
      sniff_data_to_ettercap.flags = 0;
      sniff_data_to_ettercap.proto = 'T';
      len = (len > MAX_DATA) ? MAX_DATA : len;
      sniff_data_to_ettercap.datasize = len;
      memset(&sniff_data_to_ettercap.data, 0, sizeof(sniff_data_to_ettercap.data));
      memcpy(&sniff_data_to_ettercap.data, buf, len);

      Buffer_Put(pipe_with_illithid_data, &sniff_data_to_ettercap, sizeof(SNIFFED_DATA));
   }
}

static void server_parse(char *buf, int len, public_data *son_data)
{
   CONNECTION data_to_ettercap;
   SNIFFED_DATA sniff_data_to_ettercap;
   struct in_addr source;

   memset(&data_to_ettercap, 0, sizeof(CONNECTION));
   memset(&sniff_data_to_ettercap, 0, sizeof(SNIFFED_DATA));

   source.s_addr = son_data->ServerIP;

   strncpy(data_to_ettercap.source_ip, inet_ntoa(source), sizeof(data_to_ettercap.source_ip)-1);
   data_to_ettercap.source_ip[sizeof(data_to_ettercap.source_ip)-1]='\0';
   strncpy(data_to_ettercap.dest_ip, inet_ntoa(son_data->client_sin.sin_addr), sizeof(data_to_ettercap.dest_ip)-1);
   data_to_ettercap.dest_ip[sizeof(data_to_ettercap.dest_ip)-1]='\0';

   data_to_ettercap.source_port = ntohs(son_data->ServerPort);
   data_to_ettercap.dest_port = ntohs(son_data->client_sin.sin_port);
   data_to_ettercap.source_seq = 0;
   data_to_ettercap.dest_seq = 0;
   data_to_ettercap.flags = 0;
   data_to_ettercap.proto = 'T';
   data_to_ettercap.datalen = len;

   Decodedata_MakeConnectionList(&data_to_ettercap);

   if (!Connection_Mode)
   {
      strncpy(sniff_data_to_ettercap.source_ip, inet_ntoa(source), sizeof(sniff_data_to_ettercap.source_ip)-1);
      sniff_data_to_ettercap.source_ip[sizeof(sniff_data_to_ettercap.source_ip)-1]='\0';
      strncpy(sniff_data_to_ettercap.dest_ip, inet_ntoa(son_data->client_sin.sin_addr), sizeof(sniff_data_to_ettercap.dest_ip)-1);
      sniff_data_to_ettercap.dest_ip[sizeof(sniff_data_to_ettercap.dest_ip)-1]='\0';

      sniff_data_to_ettercap.source_port = ntohs(son_data->ServerPort);
      sniff_data_to_ettercap.dest_port = ntohs(son_data->client_sin.sin_port);
      sniff_data_to_ettercap.seq = 0;
      sniff_data_to_ettercap.ack_seq = 0;
      sniff_data_to_ettercap.flags = 0;
      sniff_data_to_ettercap.proto = 'T';
      len = (len > MAX_DATA) ? MAX_DATA : len;
      sniff_data_to_ettercap.datasize = len;
      memset(&sniff_data_to_ettercap.data, 0, sizeof(sniff_data_to_ettercap.data));
      memcpy(&sniff_data_to_ettercap.data, buf, len);

      Buffer_Put(pipe_with_illithid_data, &sniff_data_to_ettercap, sizeof(SNIFFED_DATA));
   }
}


static int client_read(char *buf, size_t size, public_data *son_data)
{
   if (son_data->ssl_type) return (SSL_read(son_data->ssl_client, buf, size));
   return (read(son_data->client_fd, buf, size));
}

static int client_write(char *buf, size_t size, public_data *son_data)
{
   if (son_data->ssl_type) return (SSL_write(son_data->ssl_client, buf, size));
   return (write(son_data->client_fd, buf, size));
}

static void client_init(public_data *son_data)
{
   fcntl(son_data->client_fd, F_SETFL, 0);

   if (son_data->ssl_type)
   {
      son_data->ssl_client = SSL_new(son_data->ssl_ctx_client);
      SSL_set_fd(son_data->ssl_client, son_data->client_fd);
      SSL_accept(son_data->ssl_client);
   }
}

static void client_close(public_data *son_data)
{
   if (son_data->ssl_type) SSL_free(son_data->ssl_client);
   close(son_data->client_fd);
}

static int server_read(char *buf, size_t size, public_data *son_data)
{
   if (son_data->ssl_type) return (SSL_read(son_data->ssl_server, buf, size));
   return (read(son_data->server_fd, buf, size));
}

static int server_write(char *buf, size_t size, public_data *son_data)
{
   if (son_data->ssl_type) return (SSL_write(son_data->ssl_server, buf, size));
   return (write(son_data->server_fd, buf, size));
}

static void server_close(public_data *son_data)
{
   if (son_data->ssl_type) SSL_free(son_data->ssl_server);
   close(son_data->server_fd);
}

static int server_init(char *buf, size_t size, public_data *son_data)
{
   char vhost[501], *i=0;
   size_t offset = 0, temp;
   int type_connect=0, addr, j;
   struct hostent *toresolv=(struct hostent *)1;

   do
   {
      temp = client_read(buf + offset, size - offset, son_data);
      offset += temp;

      if (Grell_ProxyIP && !strncasecmp(buf,"CONNECT",7) && !son_data->ssl_type)
      {
         type_connect = 1;
         break;
      }

       if (temp==-1) offset=size+1;
   } while(size>=offset && (i=(char *)memmem(buf, size, "\r\nHost: ",8))==NULL);

   if (offset>=size) // No virtual host
   {
       client_close(son_data);
       return -1;
   }

   memset(&son_data->server_sin, 0, sizeof(son_data->server_sin));
   son_data->server_sin.sin_family = AF_INET;

   if (!Grell_ProxyIP || son_data->ssl_type)
   {
      memcpy(vhost, i+8, sizeof(vhost));
      vhost[500] = 0;
      strtok(vhost, "\r");
      strtok(vhost, ":");
      son_data->server_sin.sin_port = son_data->ssl_type ? htons(443) : htons(80);

      addr = inet_addr(vhost);
      if (addr == INADDR_NONE)
      {
         toresolv = gethostbyname(vhost);
         if (toresolv) addr = *(unsigned long *)toresolv->h_addr;
      }

      if (!toresolv || addr==ntohl(INADDR_LOOPBACK))
      {
         client_close(son_data);
         return -1;
      }
   }
   else
   {
       addr = Grell_ProxyIP;
       son_data->server_sin.sin_port=htons((short)Grell_ProxyPort);
   }

   son_data->server_sin.sin_addr.s_addr = addr;
   son_data->ServerIP = addr;
   son_data->ServerPort = son_data->server_sin.sin_port;

   son_data->server_fd = socket(AF_INET, SOCK_STREAM, 0);
   connect(son_data->server_fd, (struct sockaddr *)&son_data->server_sin, sizeof(son_data->server_sin));

   if (type_connect)
   {
      fd_set fds;

      server_write(buf,offset, son_data);  // Skip readable messages

      loop
      {
         FD_ZERO(&fds);
         FD_SET(son_data->client_fd, &fds);
         FD_SET(son_data->server_fd, &fds);

         select(FOPEN_MAX, &fds, 0, 0, 0);

         if (FD_ISSET(son_data->client_fd, &fds))
         {
            if ((j = client_read(buf, MAX_DATA, son_data)) <= 0)
            {
               server_close(son_data);
               client_close(son_data);
               return -1;    // if it can't handle proxy auth...
            }
            buf[j]=0;
            if (server_write(buf, j, son_data) != j)
            {
               server_close(son_data);
               client_close(son_data);
               return -1;    // if it can't handle proxy auth...
            }
         }
         else if (FD_ISSET(son_data->server_fd, &fds))
         {
            char *found;
            if ((j = server_read(buf, MAX_DATA, son_data)) <= 0)
            {
               server_close(son_data);
               client_close(son_data);
               return -1;    // if it can't handle proxy auth...
            }
            buf[j]=0;
            if (client_write(buf, j, son_data) != j)
            {
               server_close(son_data);
               client_close(son_data);
               return -1;    // if it can't handle proxy auth...
            }
            found = strstr(buf, "200");
           if ( found && (unsigned int)(found-buf) < 20 ) break;
         }
      }

      son_data->ssl_type=1;       // Turn on encryption
      client_init(son_data);
      offset = client_read(buf,MAX_DATA,son_data);

      if (offset == -1)
      {
          server_close(son_data);
          client_close(son_data);
          return -1;    // if it can't handle proxy auth...
      }
      buf[offset]=0; // Only for paranoid tests
   }

   if (son_data->ssl_type)
   {
      son_data->ssl_ctx_server = SSL_CTX_new(SSLv3_client_method());
      son_data->ssl_server = SSL_new(son_data->ssl_ctx_server);
      SSL_set_connect_state(son_data->ssl_server);
      SSL_set_fd(son_data->ssl_server, son_data->server_fd);

      if (SSL_connect(son_data->ssl_server)!=1)
      {
         son_data->ssl_ctx_server = SSL_CTX_new(SSLv2_client_method());
         son_data->ssl_server = SSL_new(son_data->ssl_ctx_server);
         SSL_set_connect_state(son_data->ssl_server);
         SSL_set_fd(son_data->ssl_server, son_data->server_fd);
         if (SSL_connect(son_data->ssl_server)!=1)
         {
            son_data->ssl_ctx_server = SSL_CTX_new(TLSv1_client_method());
            son_data->ssl_server = SSL_new(son_data->ssl_ctx_server);
            SSL_set_connect_state(son_data->ssl_server);
            SSL_set_fd(son_data->ssl_server, son_data->server_fd);
            if (SSL_connect(son_data->ssl_server)!=1)
            {
               server_close(son_data);
               client_close(son_data);
               return -1;
            }
         }
      }
   }

   return(offset);
}


void Grell_fini(void *dummy)
{
   close(proxy_fd);
   close(https_fd);

#ifdef DEBUG
   Debug_msg("Grell_fini -- grell closed gracefully...");
#endif
}


void Grell_init(void)
{
   struct sockaddr_in sa_in;
   int i=1;

   proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
   https_fd = socket(AF_INET, SOCK_STREAM, 0);

   setsockopt(proxy_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
   setsockopt(https_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

   memset(&sa_in, 0, sizeof(sa_in));
   sa_in.sin_family = AF_INET;
   sa_in.sin_addr.s_addr = INADDR_ANY;

   sa_in.sin_port = htons(Proxy_Local_Port);

   if (bind(proxy_fd, (struct sockaddr *)&sa_in, sizeof(sa_in)) < 0)
       Error_msg("Can't bind port %d (required for HTTPS dissection)\n", Proxy_Local_Port);

   sa_in.sin_port = htons(HTTPS_Local_Port);

   if (bind(https_fd, (struct sockaddr *)&sa_in, sizeof(sa_in)) < 0)
       Error_msg("Can't bind port %d (required for HTTPS dissection)\n", HTTPS_Local_Port);

#ifdef DEBUG
   Debug_msg("Grell_init -- Listening for Proxy redirect on port %d", Proxy_Local_Port);
   Debug_msg("Grell_init -- Listening for HTTPS redirect on port %d", HTTPS_Local_Port);
#endif

   listen(proxy_fd, 50);
   listen(https_fd, 50);

   SSL_library_init();

   father_data.ssl_ctx_client = SSL_CTX_new(SSLv23_server_method());

   if (SSL_CTX_use_certificate_file(father_data.ssl_ctx_client, CERT_FILE, SSL_FILETYPE_PEM) == 0)
   {
      #ifdef DEBUG
         Debug_msg("Grell_init -- SSL_CTX_use_certificate_file -- %s", DATA_PATH "/" CERT_FILE);
      #endif
      if (SSL_CTX_use_certificate_file(father_data.ssl_ctx_client, DATA_PATH "/" CERT_FILE, SSL_FILETYPE_PEM) == 0)
         Error_msg("Can't open \"%s\" file !!", CERT_FILE);
   }

   if (SSL_CTX_use_PrivateKey_file(father_data.ssl_ctx_client, CERT_FILE, SSL_FILETYPE_PEM) == 0)
   {
      #ifdef DEBUG
         Debug_msg("Grell_init -- SSL_CTX_use_PrivateKey_file -- %s", DATA_PATH "/" CERT_FILE);
      #endif
      if (SSL_CTX_use_PrivateKey_file(father_data.ssl_ctx_client, DATA_PATH "/" CERT_FILE, SSL_FILETYPE_PEM) == 0)
         Error_msg("Can't open \"%s\" file !!", CERT_FILE);
   }

   if (SSL_CTX_check_private_key(father_data.ssl_ctx_client) == 0)
      Error_msg("Bad SSL Key couple !!");

}

void * Grell_spawn(void *local_father_data)
{
   u_char buf[MAX_DATA*5];
   fd_set fds;
   int i;
   public_data son_data;

#ifdef DEBUG
   Debug_msg("Grell_spawn -- new connection accepted");
#endif

   memcpy(&son_data, local_father_data, sizeof(public_data));

   pthread_mutex_unlock(&father_mutex);

   client_init(&son_data);
   i = server_init(buf, sizeof(buf), &son_data);

   if (i == -1) return NULL;

   server_write(buf, i, &son_data);
   client_parse(buf, i, &son_data);

   loop
   {
      FD_ZERO(&fds);
      FD_SET(son_data.client_fd, &fds);
      FD_SET(son_data.server_fd, &fds);

      select(FOPEN_MAX, &fds, 0, 0, 0);

      if (FD_ISSET(son_data.client_fd, &fds))
      {
         i = sizeof(buf);
         if ((i = client_read(buf, i-2, &son_data)) <= 0) break;
         buf[i]=0;
         if (server_write(buf, i, &son_data) != i)   break;
         client_parse(buf, i, &son_data);
      }
      else if (FD_ISSET(son_data.server_fd, &fds))
      {
         i = sizeof(buf);
         if ((i = server_read(buf, i-2, &son_data)) <= 0) break;
         buf[i]=0;
         if (client_write(buf, i, &son_data) != i) break;
         server_parse(buf, i, &son_data);
      }
   }
   server_close(&son_data);
   client_close(&son_data);

   return NULL;
}

// ssl_type = 0 Proxy
// ssl_type = 1 HTTPS

void * Grell_start(void *none)
{
   fd_set fds;
   int dummy;

   Grell_init();

   fcntl(proxy_fd, F_SETFL, O_NONBLOCK);
   fcntl(https_fd, F_SETFL, O_NONBLOCK);

   exit_func(Grell_fini);

   loop
   {
      FD_ZERO(&fds);

      FD_SET(proxy_fd, &fds);
      FD_SET(https_fd, &fds);

      pthread_testcancel();

      select(FOPEN_MAX, &fds, 0, 0, (struct timeval *)0);

      pthread_testcancel();

      dummy = sizeof(struct sockaddr);

      if (FD_ISSET(proxy_fd, &fds))
      {
         u_long peer;

         #ifdef DEBUG
            Debug_msg("Grell_start -- got a connection on proxy_fd");
         #endif

         pthread_mutex_lock(&father_mutex);

         father_data.client_fd = accept(proxy_fd, (struct sockaddr *)&father_data.client_sin, &dummy);
         father_data.ssl_type = 0;

         memcpy(&peer, &father_data.client_sin.sin_addr, sizeof(u_long));
         peer &= htonl(0x00FFFFFF);
         peer |= inet_addr(Host_In_LAN[0].ip) & htonl(0xFF000000);
         memcpy(&father_data.client_sin.sin_addr, &peer, sizeof(u_long));
      }
      else if (FD_ISSET(https_fd, &fds))
      {
         u_long peer;

         #ifdef DEBUG
            Debug_msg("Grell_start -- got a connection on https_fd");
         #endif

         pthread_mutex_lock(&father_mutex);

         father_data.client_fd = accept(https_fd, (struct sockaddr *)&father_data.client_sin, &dummy);
         father_data.ssl_type = 1;

         memcpy(&peer, &father_data.client_sin.sin_addr, sizeof(u_long));
         peer &= htonl(0x00FFFFFF);
         peer |= inet_addr(Host_In_LAN[0].ip) & htonl(0xFF000000);
         memcpy(&father_data.client_sin.sin_addr, &peer, sizeof(u_long));
      }

      ECThread_create("grell_son", &Grell_spawn, &father_data);
   }

   exit_func_end();

}

pthread_t Grell_Run(void)
{
   extern DISSECTOR Available_Dissectors[];
   DISSECTOR *ds;

   for( ds = Available_Dissectors; ds->port != 0; ds++)
   {
      if (!strcasecmp("HTTPS", ds->name))
      {
         if (ds->active == 0)
         {
            #ifdef DEBUG
               Debug_msg("Grell was disabled by conf.file");
            #endif
            return 0;
         }
      }
   }

#ifdef DEBUG
   Debug_msg("Grell Starts");
#endif

   return ECThread_create("grell", &Grell_start, NULL);
}

#endif //HAVE_OPENSSL

/* EOF */
