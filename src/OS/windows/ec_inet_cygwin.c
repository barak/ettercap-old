/*
    ettercap -- inet utilities -- Module for Windows 9x/NT/2000/XP  (cygwin)

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

    $Id: ec_inet_cygwin.c,v 1.4 2002/02/11 00:57:25 alor Exp $
*/


// This file is included from ../ec_inet.c


#include <Packet32.h>

struct adapter {
	char	name[64];
	char	*desc;
	struct s {
		LPADAPTER lpAdapter;
		LPPACKET lpPacket;
	} send ;
	struct r {
		LPADAPTER lpAdapter;
		LPPACKET lpPacket;
	} recv ;
};

struct adapter lpa;

int SocketBuffer = -1;

int _Inet_OpenAdapter(char *name);
void _Inet_CloseAdapter(void);


int _Inet_OpenAdapter(char *name)
{
	u_char *buffer;
	NetType medium;

#ifdef DEBUG
   Debug_msg("_Inet_OpenAdapter");
#endif

	if ((lpa.recv.lpAdapter = PacketOpenAdapter(name)) == NULL || lpa.recv.lpAdapter->hFile == INVALID_HANDLE_VALUE)
		Error_msg("Cant open [%s]", name);

	PacketGetNetType(lpa.recv.lpAdapter, &medium);

	switch (medium.LinkType) {
		case NdisMedium802_3:
									break;
		default:
			Error_msg("Device type not supported");
	}

	if ((lpa.send.lpAdapter = PacketOpenAdapter(name)) == NULL || lpa.send.lpAdapter->hFile == INVALID_HANDLE_VALUE)
		Error_msg("Cant open [%s]", name);

	buffer = (u_char *)malloc(256000);
	if (buffer == NULL) {
		ERROR_MSG("malloc()");
	}

	/* allocate packet structure used during the capture */
	if((lpa.recv.lpPacket = PacketAllocatePacket()) == NULL)
		ERROR_MSG("Failed to allocate the LPPACKET structure.");

	PacketInitPacket(lpa.recv.lpPacket, (BYTE*)buffer, 256000);

#ifdef DEBUG
   Debug_msg("_Inet_OpenAdapter -- PacketInitPacket 256000");
#endif

	/* allocate the standard buffer in the driver */
	if(PacketSetBuff(lpa.recv.lpAdapter, 512000) == FALSE)
		ERROR_MSG("not enough memory to allocate the buffer\n");

	PacketSetReadTimeout(lpa.recv.lpAdapter, -1);

	PacketSetMinToCopy(lpa.recv.lpAdapter, 64);

	atexit(_Inet_CloseAdapter);

	return 0;
}



void _Inet_CloseAdapter(void)
{
#ifdef DEBUG
   Debug_msg("_Inet_CloseAdapter");
#endif

	PacketFreePacket(lpa.recv.lpPacket);
	PacketCloseAdapter(lpa.recv.lpAdapter);
	PacketCloseAdapter(lpa.send.lpAdapter);

}



int Inet_FindIFace(char *iface)     // adapded from eth-win32.c part of libdnet  copyright Dug Song
{
	struct adapter alist[16];
	WCHAR *name, wbuf[2048];
	ULONG wlen;
	char *desc;
	int i, j, alen;
	int dev = 0;

#ifdef DEBUG
   Debug_msg("Inet_FindIFace");
#endif

	memset(alist, 0, sizeof(alist));

	alen = sizeof(alist) / sizeof(alist[0]);
	wlen = sizeof(wbuf) / sizeof(wbuf[0]);

	PacketGetAdapterNames((char *)wbuf, &wlen);

	for (name = wbuf, i = 0; *name != '\0' && i < alen; i++) {
		wcstombs(alist[i].name, name, sizeof(alist[0].name));
		while (*name++ != '\0')
			;
	}
	for (desc = (char *)name + 2, j = 0; *desc != '\0' && j < alen; j++) {
		alist[j].desc = desc;
		while (*desc++ != '\0')
			;
	}

	printf("List of available devices :\n\n");

	for (i = 0; i < j; i++)	{
		if (!strlen(alist[i].name)) continue;
		if (!strcmp(alist[i].name, "\\Device\\Packet_NdisWanIp")) continue;	// remove the WanAdapter from the list
		#ifdef DEBUG
			Debug_msg("  --> [dev%d] - [%s]", i, alist[i].desc);
		#endif
		printf("  --> [dev%d] - [%s]\n", i, alist[i].desc);
	}

	printf("\n\nPlease select one of the above, which one ? [0]: ");
	fflush(stdout);
	scanf("%d", &dev);

#ifdef DEBUG
	Debug_msg("  --> User has selected [dev%d]", dev);
#endif

	sprintf(iface, "dev%d", dev);

	_Inet_OpenAdapter(alist[dev].name);

	sprintf(lpa.name, alist[dev].name);
	sprintf(lpa.desc, alist[dev].desc);

	return 0;
}


int Inet_CorrectIface(char *iface)
{
	struct adapter alist[16];
	WCHAR *name, wbuf[2048];
	ULONG wlen;
	char *desc;
	int i, j, alen;
	int dev = 0;

#ifdef DEBUG
   Debug_msg("Inet_CorrectIface -- [%s]", iface);
#endif

	if (strcmp(iface, "list"))		// easter egg : to get a list of interface with device name
		if (sscanf(iface, "dev%d", &dev) != 1)
			Error_msg("Incorrect device string (the format is \"dev[n]\")");

	memset(alist, 0, sizeof(alist));

	alen = sizeof(alist) / sizeof(alist[0]);
	wlen = sizeof(wbuf) / sizeof(wbuf[0]);

	PacketGetAdapterNames((char *)wbuf, &wlen);

	for (name = wbuf, i = 0; *name != '\0' && i < alen; i++) {
		wcstombs(alist[i].name, name, sizeof(alist[0].name));
		while (*name++ != '\0')
			;
	}
	for (desc = (char *)name + 2, j = 0; *desc != '\0' && j < alen; j++) {
		alist[j].desc = desc;
		while (*desc++ != '\0')
			;
	}

	for (i = 0; i < j; i++) {
		if (!strlen(alist[i].name)) continue;
		if (!strcmp(alist[i].name, "\\Device\\Packet_NdisWanIp")) continue;	// remove the WanAdapter from the list
		#ifdef DEBUG
			Debug_msg("  --> [dev%d] - [%s]", i, alist[i].desc);
		#endif
		if (strcmp(iface, "list")) {
			if (dev == i) break;
		} else {
			printf("  --> [dev%d] - [%s]\n               [%s]\n", i, alist[i].desc, alist[i].name);
		}
	}
	if (!strcmp(iface, "list")) exit(0);

	if (i == j) return -1;

	_Inet_OpenAdapter(alist[dev].name);

	sprintf(lpa.name, alist[dev].name);
	sprintf(lpa.desc, alist[dev].desc);

	return 0;
}



int Inet_GetIfaceInfo(char *iface, int *MTU, char *MyMAC, unsigned long *IP, unsigned long *NetMask)
{

	if (MTU != NULL)	*MTU = 1500; // XXX -- it is better to find the real one...

	if (MyMAC != NULL) {
		PACKET_OID_DATA *data;
		u_char buf[512];

		data = (PACKET_OID_DATA *)buf;
		data->Oid = OID_802_3_CURRENT_ADDRESS;
		data->Length = 6;

		if (PacketRequest(lpa.recv.lpAdapter, FALSE, data) == TRUE) {
			memcpy(MyMAC, data->Data, 6);
		}
	}

	if (IP != NULL) {
		u_long foo;
		PacketGetNetInfo(lpa.name, IP, &foo);
		*IP = ntohl(*IP);
	}

	if (NetMask != NULL) {
		u_long foo;
		PacketGetNetInfo(lpa.name, &foo, NetMask);
		*NetMask = ntohl(*NetMask);
	}

	return 0;
}


void Inet_CloseRawSock(int sock)
{

#ifdef DEBUG
   Debug_msg("Inet_CloseRawSock");
#endif

	close(sock);

}




int Inet_OpenRawSock(char *iface)
{

#ifdef DEBUG
   Debug_msg("Inet_OpenRawSock \t WRAPPERED TO NULL");
#endif

	return open("/dev/null", O_RDONLY, 0600 );
}



int Inet_GetRawPacket(int sock, char *buffer, int MTU, short *type)
{

   int len = 0, pktlen = 0;
   u_char *bp, *ep;
   static char MyMAC[6]={0x65,0x74,0x74,0x65,0x72,0x63};

   if (SocketBuffer == -1)                   // only the first time
   {
      SocketBuffer = Buffer_Create(1.0e5);   // 100 K buffer
      #ifdef DEBUG
         Debug_msg("Inet_GetRawPacket creates the buffer for the first time -- buf id = %d", SocketBuffer);
      #endif
   }

   Buffer_Get(SocketBuffer, &pktlen, sizeof(u_int));
   len = Buffer_Get(SocketBuffer, buffer, pktlen );

   if (type != NULL)
   {
       if (!strncmp(MyMAC,"etterc",6))    // only the first time...
           Inet_GetIfaceInfo(Options.netiface, NULL, MyMAC, NULL, NULL);
       if (!memcmp(MyMAC,buffer,6))
           *type = PACKET_HOST;
       else
           *type = !PACKET_HOST;
   }

   if (len > 0) return len;                     // there was pending fata.

	PacketReceivePacket(lpa.recv.lpAdapter, lpa.recv.lpPacket, TRUE);

	len = lpa.recv.lpPacket->ulBytesReceived;

	bp = lpa.recv.lpPacket->Buffer;

	/*
	 * Loop through each packet.
	 */

#define bhp ((struct bpf_hdr *)bp)
	ep = bp + len;
	while (bp < ep) {
		int caplen, hdrlen;
		caplen = bhp->bh_caplen;
		hdrlen = bhp->bh_hdrlen;

		Buffer_Put(SocketBuffer, &caplen, sizeof(u_int) );
      Buffer_Put(SocketBuffer, bp + hdrlen, caplen );

		bp += Packet_WORDALIGN(caplen + hdrlen);
	}
#undef bhp

   Buffer_Get(SocketBuffer, &pktlen, sizeof(u_int));
   len = Buffer_Get(SocketBuffer, buffer, pktlen );

   if (type != NULL)
   {
      if (!memcmp(MyMAC,buffer,6))
           *type = PACKET_HOST;
       else
           *type = !PACKET_HOST;
   }

	return len;
}



int Inet_SendRawPacket(int sock, char *buffer, int len)
{
	LPPACKET lpPacket;

 	if( (lpPacket = PacketAllocatePacket()) == NULL)
      ERROR_MSG("Failed to allocate the LPPACKET structure.");

	PacketInitPacket(lpPacket, buffer, len);

#ifdef DEBUG
	Debug_msg("I'm going to send %d bytes\n", len);
#endif

 	if ( PacketSendPacket(lpa.send.lpAdapter, lpPacket, TRUE) == FALSE)
 		ERROR_MSG("Failed to write to the adapter");

#ifdef DEBUG
	Debug_msg(" %d bytes sent\n", len);
#endif

 	PacketFreePacket(lpPacket);

 	return (len);
}



int Inet_SetPromisc(char *iface)
{
#ifdef DEBUG
	Debug_msg("Inet_SetPromisc");
#endif

	PacketSetHwFilter(lpa.recv.lpAdapter, NDIS_PACKET_TYPE_PROMISCUOUS);

	atexit(Inet_Restore_ifr);

	return 0;
}



void Inet_Restore_ifr(void)
{
#ifdef DEBUG
	Debug_msg("Inet_Restore_ifr");
#endif

	PacketSetHwFilter(lpa.recv.lpAdapter, NDIS_PACKET_TYPE_ALL_LOCAL);

}



void Inet_DisableForwarding(void)
{
#ifdef DEBUG
	Debug_msg("Inet_DisableForwarding: Funcion not yet implemented");
#endif
}



void Inet_RestoreForwarding(void)
{
#ifdef DEBUG
	Debug_msg("Inet_RestoreForwarding: Funcion not yet implemented");
#endif
}


char *Inet_MacFromIP(unsigned long ip)
{
	Error_msg("Inet_MacFromIP: Funcion not yet implemented");
	return NULL;
}


/* EOF */
