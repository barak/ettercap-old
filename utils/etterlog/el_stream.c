/*
    etterlog -- create, search and manipulate streams

    Copyright (C) ALoR & NaGA

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

    $Id: el_stream.c,v 1.3 2004/10/11 14:55:49 alor Exp $
*/


#include <el.h>
#include <el_functions.h>

/* protos... */

void stream_init(struct stream_object *so);
int stream_add(struct stream_object *so, struct log_header_packet *pck, char *buf);
int stream_search(struct stream_object *so, char *buf, int mode);
int stream_read(struct stream_object *so, char *buf, size_t size, int mode);
void stream_move(struct stream_object *so, size_t offset, int whence, int mode);
   
/*******************************************/

/*
 * initialize a stream object
 */
void stream_init(struct stream_object *so)
{
   TAILQ_INIT(&so->po_head);
   so->po_off = 0;
   so->pl_curr = TAILQ_FIRST(&so->po_head);
}

/*
 * add a packet to a stream
 */
int stream_add(struct stream_object *so, struct log_header_packet *pck, char *buf)
{
   struct po_list *pl, *tmp;

   /* skip ack packet or zero lenght packet */
   if (pck->len == 0)
      return 0;

   /* the packet is good, add it */
   SAFE_CALLOC(pl, 1, sizeof(struct po_list));

   /* create the packet object */
   memcpy(&pl->po.L3.src, &pck->L3_src, sizeof(struct ip_addr));
   memcpy(&pl->po.L3.dst, &pck->L3_dst, sizeof(struct ip_addr));
   
   pl->po.L4.src = pck->L4_src;
   pl->po.L4.dst = pck->L4_dst;
   pl->po.L4.proto = pck->L4_proto;
  
   SAFE_CALLOC(pl->po.DATA.data, pck->len, sizeof(char));
   
   memcpy(pl->po.DATA.data, buf, pck->len);
   pl->po.DATA.len = pck->len;
   
   /* set the stream direction */

   /* this is the first packet in the stream */
   if (TAILQ_FIRST(&so->po_head) == TAILQ_END(&so->po_head)) {
      pl->type = STREAM_SIDE1;
      /* init the pointer to the first packet */
      so->pl_curr = pl;
   /* check the previous one and set it accordingly */
   } else {
      tmp = TAILQ_LAST(&so->po_head, po_list_head);
      if (!ip_addr_cmp(&tmp->po.L3.src, &pl->po.L3.src))
         /* same direction */
         pl->type = tmp->type;
      else 
         /* change detected */
         pl->type = (tmp->type == STREAM_SIDE1) ? STREAM_SIDE2 : STREAM_SIDE1;
   }
      
   /* add to the queue */
   TAILQ_INSERT_TAIL(&so->po_head, pl, next);
   
   return pck->len;
}


/*
 * read data from the stream
 * mode can be: 
 *    STREAM_BOTH  reads from both side of the communication
 *    STREAM_SIDE1 reads only from the first side (usually client to server)
 *    STREAM_SIDE2 reads only from the other side
 */
int stream_read(struct stream_object *so, char *buf, size_t size, int mode)
{
   size_t buf_off = 0;
   size_t tmp_size = 0;

   if (mode != STREAM_BOTH) {
      /* search the first packet matching the selected mode */
      while (so->pl_curr->type != mode) {
         so->pl_curr = TAILQ_NEXT(so->pl_curr, next);
         /* don't go after the end of the stream */
         if (so->pl_curr == TAILQ_END(&so->pl_head))
            return 0;
      }
   }

   /* size is decremented while it is copied in the buffer */
   while (size) {
      /* get the size to be copied from the current po */
      tmp_size = (so->pl_curr->po.DATA.len - so->po_off < size) ? so->pl_curr->po.DATA.len - so->po_off : size;

      /* fill the buffer */
      memcpy(buf + buf_off, so->pl_curr->po.DATA.data + so->po_off, tmp_size);
      
      /* the offset is the portion of the data copied into the buffer */
      so->po_off = tmp_size;

      /* update the pointer into the buffer */
      buf_off += tmp_size;

      /* decrement the total size to be copied */
      size -= tmp_size;
      
      /* we have reached the end of the packet, go to the next one */
      if (so->po_off == so->pl_curr->po.DATA.len) {
         /* search the next packet matching the selected mode */
         do {
            so->pl_curr = TAILQ_NEXT(so->pl_curr, next);
               
            /* don't go after the end of the stream */
            if (so->pl_curr == TAILQ_END(&so->pl_head))
               return buf_off + tmp_size;
            
         } while (mode != STREAM_BOTH && so->pl_curr->type != mode);

         /* reset the offset for the packet */
         so->po_off = 0;
      }
   }
  
   /* return the total byte read */
   return buf_off + tmp_size;
}

/*
 * move the pointers into the stream
 */
void stream_move(struct stream_object *so, size_t offset, int whence, int mode)
{
   size_t tmp_size = 0;


   /* 
    * the offest is calculated from the beginning,
    * so move to the first packet
    */
   if (whence == SEEK_SET) {
      so->pl_curr = TAILQ_FIRST(&so->po_head);
      so->po_off = 0;
   }

   /* the other mode is SEEK_CUR */

   if (mode != STREAM_BOTH) {
      /* search the first packet matching the selected mode */
      while (so->pl_curr->type != mode) {
         so->pl_curr = TAILQ_NEXT(so->pl_curr, next);
         /* don't go after the end of the stream */
         if (so->pl_curr == TAILQ_END(&so->pl_head))
            return;
      }
   }

   while (offset) {
      /* get the lenght to jump to in the current po */
      tmp_size = (so->pl_curr->po.DATA.len - so->po_off < offset) ? so->pl_curr->po.DATA.len - so->po_off : offset;

      /* update the offset */
      so->po_off = tmp_size;

      /* decrement the total size to be copied */
      offset -= tmp_size;
      
      /* we have reached the end of the packet, go to the next one */
      if (so->po_off == so->pl_curr->po.DATA.len) {
         /* search the next packet matching the selected mode */
         do {
            so->pl_curr = TAILQ_NEXT(so->pl_curr, next);
               
            /* don't go after the end of the stream */
            if (so->pl_curr == TAILQ_END(&so->pl_head))
               return;
            
         } while (mode != STREAM_BOTH && so->pl_curr->type != mode);

         /* reset the offset for the packet */
         so->po_off = 0;
      }
   }
}


/*
 * search a pattern into the stream 
 */
int stream_search(struct stream_object *so, char *buf, int mode)
{
   return 0;
}


/* EOF */


// vim:ts=3:expandtab
