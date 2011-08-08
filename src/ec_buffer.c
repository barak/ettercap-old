/*
    ettercap -- comunication buffer between illithid and ettercap

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

    $Id: ec_buffer.c,v 1.5 2001/12/08 16:38:43 alor Exp $
*/

#include "include/ec_main.h"
#include "include/ec_error.h"

#define MAX_BUFFERS 10
#define HEAD_LEN 8

typedef struct {
    char *data;
    int len;
}Buffer_Data;

// global data

Buffer_Data Buffer_List[MAX_BUFFERS];
int Buffer_Index;

// protos...


int Buffer_Get(int bufferID, void *data, int size);
int Buffer_Put(int bufferID, void *data, int size);
int Buffer_Create(int len);
void Buffer_Flush(int ID);


// ----------------------------



int Buffer_Create(int len)
{
   int i;

   for (i=0; i<MAX_BUFFERS; i++)
   {
      if (!Buffer_List[i].data)
      {
         Buffer_List[i].data = (char *) calloc(len+HEAD_LEN, sizeof(char));
         Buffer_List[i].len = len;
         break;
      }
   }

   if (i == MAX_BUFFERS) i=-1;

#ifdef DEBUG
   Debug_msg("Buffer_Create -- [%d] len %d", i, len);
#endif

   return i;
}



void Buffer_Flush(int ID)
{
   if (!Buffer_List[ID].data)
      return;
   // Reset offsets
   memset(Buffer_List[ID].data, 0, HEAD_LEN);
}



int Buffer_Get(int ID, void *to_read, int size)
{
   int reprise;
   unsigned long *R_Offset, W_Offset;
   char *data;

   if (!Buffer_List[ID].data)
      return -1;

   R_Offset = (unsigned long *)Buffer_List[ID].data;
   W_Offset = *(unsigned long *)(Buffer_List[ID].data+4);
   data     = (char *)(Buffer_List[ID].data+8);


   if (*R_Offset<=W_Offset && *R_Offset+size>W_Offset)
       size = (W_Offset)-(*R_Offset);

   reprise =- Buffer_List[ID].len+(*R_Offset)+size;

   if (reprise>(long)W_Offset)
   {
       size -= reprise-(W_Offset);
       reprise = W_Offset;
   }

   if (reprise<0)
       memcpy((char *)to_read, data+(*R_Offset), size);
   else
   {
       memcpy((char *)to_read, data+(*R_Offset), size-reprise);
       memcpy(((char *)to_read)+size-reprise, data, reprise);
   }

   *R_Offset=(*R_Offset+size)%Buffer_List[ID].len;

   return size;
}




int Buffer_Put(int ID, void *to_write, int size)
{
   static int retry = 0;
   int reprise;
   unsigned long *R_Offset, *W_Offset;
   char *data;


   if (!Buffer_List[ID].data)
      return -1;

   R_Offset = (unsigned long *)Buffer_List[ID].data;
   W_Offset = (unsigned long *)(Buffer_List[ID].data+4);
   data     = (char *)(Buffer_List[ID].data+8);

   reprise  =- Buffer_List[ID].len + (*W_Offset) + size;

   while((*W_Offset<*R_Offset && *W_Offset+size>=*R_Offset) || reprise>=(long)*R_Offset)
   {
      #ifdef DEBUG
         Debug_msg("Buffer_Put -- %d BUFFER FULL !! buff len [%d] byte lost [%d]", ID, Buffer_List[ID].len, size);
      #endif
      if (retry >= 2)
      {
         retry = 0;
         return 0;
      }
      retry++;
      usleep(500);
   }

   retry = 0;

   if (reprise<=0)
       memcpy(data+*W_Offset, (char *)to_write, size);
   else
   {
       memcpy(data+*W_Offset, (char *)to_write, size-reprise);
       memcpy(data, ((char *)to_write)+size-reprise ,reprise);
   }

   *W_Offset = (*W_Offset+size)%Buffer_List[ID].len;

   return 0;

}


/* EOF */

