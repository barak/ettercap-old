/*
    dummy -- ettercap plugin -- it does nothig !
                                only demostrates how to write a plugin !

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

    $Id: H99_dummy.c,v 1.1 2001/09/27 19:07:40 alor Exp $
*/


#include "../../src/include/ec_main.h"                   /* required for global variables */
#include "../../src/include/ec_plugins.h"                /* required for input/output and plugin ops*/

#include <stdlib.h>
#include <string.h>

// protos...

int Plugin_Init(void *);                                 /* prototypes is required for -Wmissing-prototypes */
int Plugin_Fini(void *);
int dummy_function(void *data);

// plugin operation

struct plugin_ops ops = {
   ettercap_version: VERSION,                                     /* ettercap version MUST be the global VERSION */
   plug_info:        "Dummy hooking plugin. It does nothing !",   /* a short description of the plugin (max 50 chars) */
   plug_version:     20,                                          /* the plugin version. note: 15 will be displayed as 1.5 */
   plug_type:        PT_HOOK,                                     /* the pluging type: external (PT_EXT) or hooking (PT_HOOK) */
   hook_point:       PCK_DISSECTOR,                               /* the hook point */
   hook_function:    &dummy_function,                             /* function to be executed */
};

//==================================

int Plugin_Init(void *params)                            /* this function is called on plugin load */
{

   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as Plugin_Register()
    *  the opaque pointer params MUST be passed to Plugin_Register()
    */
   return Plugin_Register(params, &ops);
}

int Plugin_Fini(void *params)                            /* this function is called on plugin unload */
{
   return 0;
}

// =================================

int dummy_function(void *data)                           /* required: hooking function */
{
   DISSECTION *data_to_ettercap;
   static int tcp_packets = 0;
   static int udp_packets = 0;
   static int tcp_lenght = 0;
   static int udp_lenght = 0;

   data_to_ettercap = (DISSECTION *)data;                /* convert the opaque poiter (void *) to something comprehensible */

   if (data_to_ettercap->connection->proto == 'T')
   {
      tcp_packets++;
      tcp_lenght += data_to_ettercap->connection->datalen;
   }

   if (data_to_ettercap->connection->proto == 'U')
   {
      udp_packets++;
      udp_lenght += data_to_ettercap->connection->datalen;
   }

   /*
    * NOTE: every call to Plugin_Hook_Output() causes the previous output to be flushed.
    *       so create the entire output in a string then print it.
    */

   Plugin_Hook_Output("Dummy statistics plugin:\n"
                      "%4d TCP packets:  %d bytes\n"
                      "%4d UDP packets:  %d bytes\n",
                       tcp_packets, tcp_lenght,
                       udp_packets, udp_lenght);

   return 0;
}

/* EOF */
