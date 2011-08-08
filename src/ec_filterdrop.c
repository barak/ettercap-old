/*
    ettercap -- module for filtering or dropping packets that match criteria

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

    $Id: ec_filterdrop.c,v 1.5 2001/12/06 17:53:01 alor Exp $
*/

#include "include/ec_main.h"

#include <errno.h>
#include <sys/types.h>
#ifdef HAVE_CTYPE_H
   #include <ctype.h>
#endif

#include "include/ec_inet_structures.h"
#include "include/ec_inet_forge.h"
#include "include/ec_logtofile.h"
#include "include/ec_error.h"

#define MOD_LOG      3
#define MOD_DROP     2
#define MOD_REPLACED 1
#define MOD_ORIG     0

pthread_mutex_t filter_mutex = PTHREAD_MUTEX_INITIALIZER;

DROP_FILTER *Filter_Array_Source;   // ec_main.h
DROP_FILTER *Filter_Array_Dest;
int Filter_Source;
int Filter_Dest;

char *Filter_File;

int validation = 0;

// protos

int FilterDrop_MakefilterTCP(u_char *buf_ip, int *buflen, short maxlen, DROP_FILTER *filter, char *mod);
int FilterDrop_MakefilterUDP(u_char *buf_ip, int *buflen, short maxlen, DROP_FILTER *filter, char *mod);
int FilterDrop_DoFilter(u_char *buf, int *buflen, short maxlen, DROP_FILTER *filter, short *next_filter, char *mod);
int FilterDrop_strescape(char *dst, char *src);
void FilterDrop_AddFilter(DROP_FILTER *ptr);
void FilterDrop_DelFilter(DROP_FILTER *ptr, int i);
void FilterDrop_SaveFilter(void);
int FilterDrop_CheckMode(DROP_FILTER *ptr, short mode);
int FilterDrop_MatchPorts(char p, char fp, int s, int fs, int d, int fd);
int FilterDrop_ParseWildcard(char *dst, char *src, size_t siz);
int FilterDrop_Validation(DROP_FILTER *ptr);
int Filter_DoValidate(DROP_FILTER *ptr, short i);


// -------------------------------

int FilterDrop_MakefilterTCP(u_char *buf_ip, int *buflen, short maxlen, DROP_FILTER *filters, char *mod)
{
   u_char *data;
   int droplen, datalen, i=0, ret=0;
   int delta = 0;
   short next_filter = -1;
   IP_header *ip;
   TCP_header *tcp;

   ip = (IP_header *) buf_ip;
   tcp = (TCP_header *) ((int)ip + ip->h_len * 4);
   data = (char *)((int)tcp + tcp->doff * 4);
   droplen = datalen = (int)ip + ntohs(ip->t_len) - (int)data;
   maxlen -= ((int)data-(int)ip);                     // MTU - (ip + tcp header)

   *mod = MOD_ORIG;  // no modification
   if (!filters) return 0;  // no filters... no action...

   pthread_mutex_lock(&filter_mutex);

   do
   {
      if ( !FilterDrop_MatchPorts('T', filters[i].proto, ntohs(tcp->source), filters[i].source, ntohs(tcp->dest), filters[i].dest))
      {
         i = next_filter = filters[i].else_go_to;
      }
      else
      {
         ret = FilterDrop_DoFilter(data, &datalen, maxlen*2, &filters[i], &next_filter, mod);

         if (*mod == MOD_LOG)    // log the packet
            LogToFile_FilteredData(buf_ip);
         else
         {
            if (*mod == MOD_DROP)   // drop the packet
            {
               delta = -droplen;
               break;
            }
            else delta += ret;
         }
         i = next_filter;
      }
   } while (next_filter >= 0);

   ip->t_len = htons(ntohs(ip->t_len) + delta);

   *buflen += delta;

   pthread_mutex_unlock(&filter_mutex);

   return delta;
}


int FilterDrop_MakefilterUDP(u_char *buf_ip, int *buflen, short maxlen, DROP_FILTER *filters, char *mod)
{
   u_char *data;
   int droplen, datalen, i=0, ret;
   int delta = 0;
   short next_filter = -1;
   IP_header *ip;
   UDP_header *udp;

   ip = (IP_header *) buf_ip;
   udp = (UDP_header *) ((int)ip + ip->h_len * 4);
   data = (char *)((int)udp + UDP_HEADER);
   droplen = datalen = ntohs(udp->len) - UDP_HEADER;
   maxlen -= UDP_HEADER;                     // MTU - (udp header)

   *mod = MOD_ORIG;  // no modification
   if (!filters) return 0;  // no filters... no action...

   pthread_mutex_lock(&filter_mutex);

   do
   {
      if ( !FilterDrop_MatchPorts('U', filters[i].proto, ntohs(udp->source), filters[i].source, ntohs(udp->dest), filters[i].dest))
      {
         i = next_filter = filters[i].else_go_to;
      }
      else
      {
         ret = FilterDrop_DoFilter(data, &datalen, maxlen, &filters[i], &next_filter, mod);

         if (*mod == MOD_LOG)    // log the packet
            LogToFile_FilteredData(buf_ip);
         else if (*mod == MOD_DROP) // drop the packet
         {
            delta = -droplen;
            break;
         }
         else
            delta += ret;

         i = next_filter;
      }
   } while (next_filter >= 0);

   ip->t_len = htons(ntohs(ip->t_len) + delta);
   udp->len = htons(ntohs(udp->len) + delta);

   *buflen += delta;

   pthread_mutex_unlock(&filter_mutex);

   return delta;

}

int FilterDrop_DoFilter(u_char *buf, int *buflen, short maxlen, DROP_FILTER *filter, short *next_filter, char *mod)
{
   u_char *ptr = buf;
   int found = 0;
   int rest;
   int end = *buflen;
   int delta = 0;

   if (filter->slen == 0)  // zero length strings always match the filter...
   {
      *next_filter = filter->go_to;
      if (filter->type == 'L')   // log this packet to a file
      {
         *mod = MOD_LOG;
         return 0;
      }
      if (filter->type == 'D')   // drop the packet
      {
         *mod = MOD_DROP;
         *next_filter = -1;
          return -*buflen;
      }
      return 0;
   }

   do    // first we check that after replacement the size will be within maxlen...
   {
      rest = *buflen-((u_int)ptr-(u_int)buf);
      ptr = (u_char *)memmem(ptr, rest, filter->search, filter->slen);

      if (ptr != NULL)
      {
         // we have found the search string...
         *next_filter = filter->go_to;
         if (filter->type == 'L')   // log this packet to a file
         {
            *mod = MOD_LOG;
            return 0;
         }
         if (filter->type == 'D')            // drop the packet
         {
            *mod = MOD_DROP;
            *next_filter = -1;
             return -*buflen;
         }

         delta += (filter->rlen - (filter->slen + filter->wildcard));
         end = *buflen + delta;
         if (end > maxlen)
         {
            #ifdef DEBUG
               Debug_msg("FilterDrop_DoFilter -- maxlen reached !! %d/%d from %d [%d][%d]", end, maxlen, *buflen, found, (filter->rlen - filter->slen) );
            #endif
            return 0;
         }
         ptr = (u_char *)((int)ptr + (filter->slen + filter->wildcard));   // move the ptr after the replaced string
         found++;
      }

   }while (ptr != NULL);

   if (!found)
   {
      *next_filter = filter->else_go_to;
      return 0;
   }

   if (filter->type != 'R' || !*buflen) return 0;

   ptr = buf;
   end = *buflen;
   delta = 0;

   do    // then we make the replacement...
   {
      rest = end-((u_int)ptr-(u_int)buf);
      ptr = (u_char *)memmem(ptr, rest , filter->search, filter->slen);
      rest = end-((u_int)ptr-(u_int)buf) - (filter->slen + filter->wildcard);

      if (ptr != NULL)
      {
         memmove(ptr + filter->rlen, ptr + (filter->slen + filter->wildcard), rest);
         memcpy(ptr, filter->replace, filter->rlen);
         *mod = MOD_REPLACED; // mark the packet modified in order to recalculate the checksum.
         ptr = (u_char *)((int)ptr + filter->rlen);   // move the ptr after the replaced string
         delta += (filter->rlen - (filter->slen + filter->wildcard));
         end = *buflen + delta;
      }

   }while (ptr != NULL);

   *buflen = end;

   return (found) ? delta : 0;

}


int FilterDrop_MatchPorts(char p, char fp, int s, int fs, int d, int fd)
{
   char oks=0, okd=0;

   if (p != fp) return 0;

   if (fs == 0) oks = 1;   // any port it is ok !
   if (fd == 0) okd = 1;

   if ( s == fs ) oks = 1;
   if ( d == fd ) okd = 1;

   return (oks && okd);
}



int FilterDrop_CheckMode(DROP_FILTER *ptr, short mode)
{
   int i, n=0;

   if (mode == ARPBASED) return 0;

   if (ptr == Filter_Array_Source) n = Filter_Source;
   else if (ptr == Filter_Array_Dest) n = Filter_Dest;

   for(i=0; i<n; i++)
   {
      if ( (ptr[i].type == 'R') || (ptr[i].type == 'D') )
         return 1;
   }

   return 0;
}



int FilterDrop_ParseWildcard(char *dst, char *src, size_t size)
{
   int j=0, k=0;
   char *p, *q;

   strlcpy(dst, src, size);
   p = dst;

   if ( (q = strstr(p, "*]")) )
   {
      q--;
      while (*q != '[' && q > p && isdigit((int)*q) )   // q > string init and search for the [
      {
         q--;
         k++;
      }
      sscanf(q, "[%d*]", &j);
      if (j) *q = 0;
   }

   return j;

}



int Filter_DoValidate(DROP_FILTER *ptr, short i)
{
   int G=0, E=0;

   if (ptr[i].validate == validation) return 1;

   ptr[i].validate = validation;

   if (ptr[i].go_to != -1)
      G = Filter_DoValidate(ptr, ptr[i].go_to);       // recursively scan the oriented graph

   ptr[i].validate = validation;

   if (ptr[i].else_go_to != -1 && G == 0)
      E = Filter_DoValidate(ptr, ptr[i].else_go_to);  // recursively scan the oriented graph

   validation++;

   return (G || E);
}



int FilterDrop_Validation(DROP_FILTER *ptr)
{
   int i, V=0;

#ifdef DEBUG
   Debug_msg("FilterDrop_Validation");
#endif

   validation = 1;

   if (ptr == Filter_Array_Source)
   {
      if (Filter_Array_Source == NULL) return 0;

      for (i=0; i<Filter_Source; i++)
      {
         Filter_Array_Source[i].validate = 0;
         if (Filter_Array_Source[i].go_to >= Filter_Source ) return 2;
         if (Filter_Array_Source[i].else_go_to >= Filter_Source ) return 2;
      }

      V = Filter_DoValidate(Filter_Array_Source, 0);
   }
   else if (ptr == Filter_Array_Dest)
   {
      if (Filter_Array_Dest == NULL) return 0;

      for (i=0; i<Filter_Dest; i++)
      {
         Filter_Array_Dest[i].validate = 0;
         if (Filter_Array_Dest[i].go_to >= Filter_Dest ) return 2;
         if (Filter_Array_Dest[i].else_go_to >= Filter_Dest ) return 2;
      }

      V = Filter_DoValidate(Filter_Array_Dest, 0);
   }

#ifdef DEBUG
   Debug_msg("FilterDrop_Validation -- %d", V);
#endif

   return V;

}



void FilterDrop_AddFilter(DROP_FILTER *ptr)
{

   DROP_FILTER newfilter;

#ifdef DEBUG
   Debug_msg("FilterDrop_AddFilter");
#endif

   pthread_mutex_lock(&filter_mutex);

   memset(&newfilter, 0, sizeof(DROP_FILTER));
   newfilter.go_to = -1;
   newfilter.else_go_to = -1;
   newfilter.proto = 'T';

   if (ptr == Filter_Array_Source)
   {
      Filter_Source++;
      Filter_Array_Source = (DROP_FILTER *)realloc(Filter_Array_Source, (Filter_Source) * sizeof(DROP_FILTER));
      memcpy(&Filter_Array_Source[Filter_Source-1], &newfilter, sizeof(DROP_FILTER));
   }
   else if (ptr == Filter_Array_Dest)
   {
      Filter_Dest++;
      Filter_Array_Dest = (DROP_FILTER *)realloc(Filter_Array_Dest, (Filter_Dest) * sizeof(DROP_FILTER));
      memcpy(&Filter_Array_Dest[Filter_Dest-1], &newfilter, sizeof(DROP_FILTER));
   }

   pthread_mutex_unlock(&filter_mutex);
}



void FilterDrop_DelFilter(DROP_FILTER *ptr, int i)
{
   int num_filter=0, j, k;

#ifdef DEBUG
   Debug_msg("FilterDrop_DelFilter -- %d", i);
#endif

   pthread_mutex_lock(&filter_mutex);

   if (ptr == Filter_Array_Source)
   {
      num_filter = Filter_Source;
      Filter_Source = (Filter_Source > 0) ? Filter_Source-1 : 0;
   }
   else if (ptr == Filter_Array_Dest)
   {
      num_filter = Filter_Dest;
      Filter_Dest = (Filter_Dest > 0) ? Filter_Dest-1 : 0;
   }

   for (j=0; j<num_filter; j++)
   {
      if (ptr[j].go_to == i) ptr[j].go_to = -1;
      if (ptr[j].else_go_to == i) ptr[j].else_go_to = -1;
      if (ptr[j].go_to > i) ptr[j].go_to--;
      if (ptr[j].else_go_to > i) ptr[j].else_go_to--;
      if (j == i)
      {
         for(k=j+1; k<num_filter; k++ )
         {
            memcpy(&ptr[k-1], &ptr[k], sizeof(DROP_FILTER));
            if (ptr[k-1].go_to == i) ptr[k-1].go_to = -1;
            if (ptr[k-1].else_go_to == i) ptr[k-1].else_go_to = -1;
            if (ptr[k-1].go_to > i) ptr[k-1].go_to--;
            if (ptr[k-1].else_go_to > i) ptr[k-1].else_go_to--;
         }
         break;
      }
   }

   pthread_mutex_unlock(&filter_mutex);

}



void FilterDrop_SaveFilter(void)
{
   FILE *etterfilter;
   int i;

   etterfilter = fopen(Filter_File, "w");
   if (etterfilter == NULL)
      ERROR_MSG("fopen()");

   fprintf(etterfilter, "############################################################################\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "#  ettercap -- etter.filter -- filter chain file                           #\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "#  Copyright (C) 2001  ALoR <alor@users.sourceforge.net>                   #\n");
   fprintf(etterfilter, "#                      NaGA <crwm@freemail.it>                             #\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "#  This program is free software; you can redistribute it and/or modify    #\n");
   fprintf(etterfilter, "#  it under the terms of the GNU General Public License as published by    #\n");
   fprintf(etterfilter, "#  the Free Software Foundation; either version 2 of the License, or       #\n");
   fprintf(etterfilter, "#  (at your option) any later version.                                     #\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "############################################################################\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "#  Filtering chains, in pseudo XML format.                                 #\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "# You can write by hand this file or (better) use the ncurses interface to #\n");
   fprintf(etterfilter, "# let ettercap create it.                                                  #\n");
   fprintf(etterfilter, "# If you are skilled in XML parsing, you can write your own program to     #\n");
   fprintf(etterfilter, "# make a filter chain file.                                                #\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "# the rules are simple:                                                    #\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "#  If the proto <proto> and the source port <source> and the dest port     #\n");
   fprintf(etterfilter, "#  <dest> and the payload <search> match the rules, after the filter       #\n");
   fprintf(etterfilter, "#  as done its action (<action>), it jumps in the chain to the filter id   #\n");
   fprintf(etterfilter, "#  specified in the <goto> field, else it jumps to <elsegoto>.             #\n");
   fprintf(etterfilter, "#  If these field are left blank the chain is interrupted.                 #\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "#  Source and dest port equal to 0 (zero) means ANY port.                  #\n");
   fprintf(etterfilter, "#                                                                          #\n");
   fprintf(etterfilter, "############################################################################\n\n\n");
   fprintf(etterfilter, "##############################\n");
   fprintf(etterfilter, "#### FILTER ON SOURCE IP #####\n");
   fprintf(etterfilter, "##############################\n\n");
   for(i=0; i < Filter_Source; i++)
   {
      fprintf(etterfilter, "<filter source>\n");
      fprintf(etterfilter, "\t<id>%d</id>\n", i);
      fprintf(etterfilter, "\t<proto>%c</proto>\n", Filter_Array_Source[i].proto);
      fprintf(etterfilter, "\t<source>%d</source>\n", Filter_Array_Source[i].source);
      fprintf(etterfilter, "\t<dest>%d</dest>\n", Filter_Array_Source[i].dest);
      fprintf(etterfilter, "\t<search>%s</search>\n", Filter_Array_Source[i].display_search);
      fprintf(etterfilter, "\t<action>%c</action>\n", Filter_Array_Source[i].type);
      fprintf(etterfilter, "\t<replace>%s</replace>\n", Filter_Array_Source[i].display_replace);
      if (Filter_Array_Source[i].go_to >= 0)
         fprintf(etterfilter, "\t<goto>%d</goto>\n", Filter_Array_Source[i].go_to);
      else
         fprintf(etterfilter, "\t<goto></goto>\n");
      if (Filter_Array_Source[i].else_go_to >= 0)
         fprintf(etterfilter, "\t<elsegoto>%d</elsegoto>\n", Filter_Array_Source[i].else_go_to);
      else
         fprintf(etterfilter, "\t<elsegoto></elsegoto>\n");
      fprintf(etterfilter, "</filter source>\n\n");
   }
   fprintf(etterfilter, "############################\n");
   fprintf(etterfilter, "#### FILTER ON DEST IP #####\n");
   fprintf(etterfilter, "############################\n\n");
   for(i=0; i < Filter_Dest; i++)
   {
      fprintf(etterfilter, "<filter dest>\n");
      fprintf(etterfilter, "\t<id>%d</id>\n", i);
      fprintf(etterfilter, "\t<proto>%c</proto>\n", Filter_Array_Dest[i].proto);
      fprintf(etterfilter, "\t<source>%d</source>\n", Filter_Array_Dest[i].source);
      fprintf(etterfilter, "\t<dest>%d</dest>\n", Filter_Array_Dest[i].dest);
      fprintf(etterfilter, "\t<search>%s</search>\n", Filter_Array_Dest[i].display_search);
      fprintf(etterfilter, "\t<action>%c</action>\n", Filter_Array_Dest[i].type);
      fprintf(etterfilter, "\t<replace>%s</replace>\n", Filter_Array_Dest[i].display_replace);
      if (Filter_Array_Dest[i].go_to >= 0)
         fprintf(etterfilter, "\t<goto>%d</goto>\n", Filter_Array_Dest[i].go_to);
      else
         fprintf(etterfilter, "\t<goto></goto>\n");
      if (Filter_Array_Dest[i].else_go_to >= 0)
         fprintf(etterfilter, "\t<elsegoto>%d</elsegoto>\n", Filter_Array_Dest[i].else_go_to);
      else
         fprintf(etterfilter, "\t<elsegoto></elsegoto>\n");
      fprintf(etterfilter, "</filter dest>\n\n");
   }

   fclose(etterfilter);

}



// adapted from magic.c part of dsniff <dugsong@monkey.org> source code...


static int hextoint(int c)
{
   if (!isascii((int) c))       return (-1);
   if (isdigit((int) c))        return (c - '0');
   if ((c >= 'a') && (c <= 'f'))   return (c + 10 - 'a');
   if ((c >= 'A') && (c <= 'F'))   return (c + 10 - 'A');
   return (-1);
}

int FilterDrop_strescape( char *dst, char *src)
{
   char  *olddst = dst;
   int   c;
   int   val;

   while ((c = *src++) != '\0')
   {
      if (c == '\\')
      {
         switch ((c = *src++))
         {
            case '\0':
               goto strend;
            default:
               *dst++ = (char) c;
               break;
            case 'n':
               *dst++ = '\n';
               break;
            case 'r':
               *dst++ = '\r';
               break;
            case 'b':
               *dst++ = '\b';
               break;
            case 't':
               *dst++ = '\t';
               break;
            case 'f':
               *dst++ = '\f';
               break;
            case 'v':
               *dst++ = '\v';
               break;
            /* \ and up to 3 octal digits */
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
               val = c - '0';
               c = *src++;  /* try for 2 */
               if (c >= '0' && c <= '7') {
                  val = (val << 3) | (c - '0');
                  c = *src++;  /* try for 3 */
                  if (c >= '0' && c <= '7')
                     val = (val << 3) | (c - '0');
                  else --src;
               }
               else --src;
               *dst++ = (char) val;
               break;

            case 'x':
               val = 'x';      /* Default if no digits */
               c = hextoint(*src++);     /* Get next char */
               if (c >= 0) {
                       val = c;
                       c = hextoint(*src++);
                       if (c >= 0) val = (val << 4) + c;
                       else --src;
               }
               else --src;
               *dst++ = (char) val;
               break;
         }
      }
      else if (c == 8 || c == 263)  // the backspace
         dst--;
      else
         *dst++ = (char) c;
   }

strend:
   *dst = '\0';

   return (dst - olddst);
}



/* EOF */
