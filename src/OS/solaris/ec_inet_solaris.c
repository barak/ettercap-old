/*
    ettercap -- inet utilities -- Module for SunOS (solaris)

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

    $Id: ec_inet_solaris.c,v 1.9 2002/02/11 01:15:48 alor Exp $
*/


// This file is included from ../ec_inet.c


#include <sys/ioctl.h>
#include <sys/sockio.h>

#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_BUFMOD_H
#include <sys/bufmod.h>
#endif
#include <sys/dlpi.h>
#ifdef HAVE_SYS_DLPI_EXT_H
#include <sys/dlpi_ext.h>
#endif

#include <sys/stream.h>
#ifdef HAVE_SYS_BUFMOD_H
#include <sys/systeminfo.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

struct ether_addr
{
   u_char  ether_addr_octet[6];
};

#ifndef DLPI_DEV_PREFIX
#define DLPI_DEV_PREFIX "/dev"
#endif

#define  MAXDLBUF 8192

/* protos... */
static int dlattachreq(int, u_int, char *);
static int dlbindack(int, char *, char *);
static int dlbindreq(int, u_int, char *);
static int dlinfoack(int, char *, char *);
static int dlinforeq(int, char *);
static int dlokack(int, const char *, char *, char *);
static int send_request(int, char *, int, char *, char *);
static int recv_ack(int, int, const char *, char *, char *);
static int dlpromisconreq(int, u_int, char *);
#if defined(SOLARIS) && defined(HAVE_SYS_BUFMOD_H)
static char *get_release(u_int *, u_int *, u_int *);
#endif
#ifdef HAVE_SYS_BUFMOD_H
static int strioctl(int, int, int, char *);
#endif
#ifdef HAVE_DEV_DLPI
static int get_dlpi_ppa(int, const char *, int, char *);
#endif
static char * split_dname(char *device, int *unitp);

int fdprom;
static u_int ctlbuf[MAXDLBUF];
static struct strbuf ctl = {
   MAXDLBUF,
   0,
   (char *)ctlbuf
};
char ebuf[100];

int bufsize, offset;
int SocketBuffer = -1;

// ==============================================

int Inet_FindIFace(char *iface)     // adapded from pcap_lookupdev
{
   int fd, minunit, n;
   char *cp;
   struct ifreq *ifrp, *ifend, *ifnext, *mp;
   struct ifconf ifc;
   char *buf;
   struct ifreq ifr;
   unsigned int buf_size;

   fd = socket(AF_INET, SOCK_DGRAM, 0);
   if (fd < 0)
      Error_msg("ec_inet_solaris:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   buf_size = 8192;

   for (;;) {
      buf = malloc (buf_size);
      if (buf == NULL)
         Error_msg("ec_inet_solaris:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

      ifc.ifc_len = buf_size;
      ifc.ifc_buf = buf;
      memset (buf, 0, buf_size);
      if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0 && errno != EINVAL)
         Error_msg("ec_inet_solaris:%d ioctl(SIOCGIFCONF) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

      if (ifc.ifc_len < buf_size)
         break;

      free (buf);
      buf_size *= 2;
   }

   ifrp = (struct ifreq *)buf;
   ifend = (struct ifreq *)(buf + ifc.ifc_len);

   mp = NULL;
   minunit = 666;
   for (; ifrp < ifend; ifrp = ifnext)
   {
      const char *endcp;

#ifdef HAVE_SOCKADDR_SA_LEN
   n = ifrp->ifr_addr.sa_len + sizeof(ifrp->ifr_name);
   if (n < sizeof(*ifrp))
      ifnext = ifrp + 1;
   else
      ifnext = (struct ifreq *)((char *)ifrp + n);
   if (ifrp->ifr_addr.sa_family != AF_INET)
      continue;
#else
   ifnext = ifrp + 1;
#endif

      strncpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));

      if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr) < 0)
      {
         if (errno == ENXIO)
            continue;
         Error_msg("ec_inet_solaris:%d ioctl(SIOCGIFFLAGS) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
      }

#ifdef DEBUG
   Debug_msg("Inet_FindIFace -- check for [%s]", ifr.ifr_name);
#endif

      /* Must be up and not the loopback */
      if ((ifr.ifr_flags & IFF_UP) == 0 || (ifr.ifr_flags & IFF_LOOPBACK) != 0)
         continue;

      endcp = ifrp->ifr_name + strlen(ifrp->ifr_name);
      for (cp = ifrp->ifr_name; cp < endcp && !isdigit((int)*cp); ++cp)
         continue;

      if (isdigit ((int)*cp)) {
         n = atoi(cp);
      } else {
         n = 0;
      }
      if (n < minunit) {
         minunit = n;
         mp = ifrp;
      }
   }

   close(fd);

   if (mp == NULL)   // no device found
   {
      free(buf);
      return -1;
   }

   strlcpy(iface, mp->ifr_name, sizeof(Options.netiface));

   free(buf);

#ifdef DEBUG
   Debug_msg("Inet_FindIFace -- %s found !!", iface);
#endif

   return 0;

}


int Inet_CorrectIface(char *iface)
{
   int sock;
   struct ifreq ifr;

#ifdef DEBUG
   Debug_msg("Inet_CorrectIface\t\tIface: %s", iface);
#endif

   sock = socket(AF_INET, SOCK_DGRAM, 0);
   if (sock < 0)
      Error_msg("ec_inet_solaris:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
   if ( ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)             // check for iface
   {
      close(sock);
      return -1;
   }

   if (!(ifr.ifr_flags & IFF_UP ))                       // check for flag UP
   {
      close(sock);
      return -1;
   }

   if (ifr.ifr_flags & IFF_LOOPBACK )                    // check for loopback
   {
      Options.normal = 1;
      Error_msg("Ettercap can't be run on loopback device");
   }

   if ( ioctl(sock, SIOCGIFADDR, &ifr) < 0 )             // check for alias
   {
      close(sock);
      return -1;
   }

   close(sock);

   return 0;

}



int Inet_GetIfaceInfo(char *iface, int *MTU, char *MyMAC, unsigned long *IP, unsigned long *NetMask)
{
   int sock, dlpi;
   struct ifreq ifr;

   sock = socket(PF_INET, SOCK_DGRAM, 0);

   dlpi = Inet_OpenRawSock(iface);

   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

   if (MTU != NULL)
   {
      if ( ioctl(sock, SIOCGIFMTU, &ifr) < 0)
      {
         #ifdef DEBUG
            Debug_msg("Inet_GetIfaceInfo -- MTU FAILED... assuming 1500");
         #endif
         *MTU = 1500;
      }
      else
// FIXME
         //*MTU = ifr.ifr_mtu;
         *MTU = ifr.ifr_metric;  // ?? possible ?? i've found this example on the web...
   }

   if (MyMAC != NULL)
   {
      char buf[2048];
      union DL_primitives *dlp;

      dlp = (union DL_primitives*) buf;

      dlp->physaddr_req.dl_primitive = DL_PHYS_ADDR_REQ;
      dlp->physaddr_req.dl_addr_type = DL_CURR_PHYS_ADDR;

      if (send_request(dlpi, (char *)dlp, DL_PHYS_ADDR_REQ_SIZE, "physaddr", ebuf) < 0)
         Error_msg("ec_inet_solaris:%d send_request(DL_PHYS_ADDR_REQ_SIZE) | %s \n", __LINE__, ebuf);

      if (recv_ack(dlpi, DL_PHYS_ADDR_ACK_SIZE, "physaddr", (char *)dlp, ebuf) < 0)
         Error_msg("ec_inet_solaris:%d recv_ack(DL_PHYS_ADDR_ACK_SIZE) | %s \n", __LINE__, ebuf);

      memcpy( MyMAC,(struct ether_addr *) ((char *) dlp + dlp->physaddr_ack.dl_addr_offset), ETHER_ADDR_LEN);

      Inet_CloseRawSock(dlpi);
   }

   if (IP != NULL)
   {
      if ( ioctl(sock, SIOCGIFADDR, &ifr) < 0 )
         Error_msg("ec_inet_solaris:%d ioctl(SIOCGIFADDR) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
      memcpy((char *)IP, ifr.ifr_addr.sa_data+2, 4);
   }

   if (NetMask != NULL)
   {
      if ( ioctl(sock, SIOCGIFNETMASK, &ifr) < 0 )
         Error_msg("ec_inet_solaris:%d ioctl(SIOCGIFNETMASK) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
      memcpy((char *)NetMask, ifr.ifr_addr.sa_data+2, 4);
      if (strcmp(Options.netmask, ""))       // specified on command line
         *NetMask = inet_addr(Options.netmask);
   }

   close(sock);

   return 0;

}


void Inet_CloseRawSock(int sock)
{

#ifdef DEBUG
   Debug_msg("Inet_CloseRawSock \t fd = %d", sock);
#endif

   close(sock);

}




int Inet_OpenRawSock(char *iface)      // adapted from libpcap source code
{
   register char *cp;
   int fd;
   int ppa;
   register dl_info_ack_t *infop;
#ifdef HAVE_SYS_BUFMOD_H
   u_long flag, ss;
   char *release;
   u_int osmajor, osminor, osmicro;
#endif
   u_long buf[MAXDLBUF];
   char dname[100];
#ifndef HAVE_DEV_DLPI
   char dname2[100];
#endif


#ifdef HAVE_DEV_DLPI
   /*
   ** Remove any "/dev/" on the front of the device.
   */
   cp = strrchr(iface, '/');
   if (cp == NULL)
      cp = iface;
   else
      cp++;
   strlcpy(dname, cp, sizeof(dname));

   /*
    * Split the name into a device type and a unit number.
    */
   //cp = strpbrk(dname, "0123456789");

   cp = split_dname(dname, &ppa);
   if (cp == NULL)
      Error_msg("ec_inet_solaris:%d HAVE_DEV_DLPI: %s missing or bad unit number\n", __LINE__, iface);

	*cp = '\0';

   /*
    * Use "/dev/dlpi" as the device.
    */

   cp = "/dev/dlpi";
   if ((fd = open(cp, O_RDWR)) < 0)
      Error_msg("ec_inet_solaris:%d open() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   /*
    * Get a table of all PPAs for that device, and search that
    * table for the specified device type name and unit number.
    */
   ppa = get_dlpi_ppa(fd, dname, ppa, ebuf);
   if (ppa < 0)
      Error_msg("ec_inet_solaris:%d get_dlpi_ppa() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

#else
   /*
   ** Determine device and ppa
   */
   cp = split_dname(iface, &ppa);
   if (cp == NULL)
      Error_msg("ec_inet_solaris:%d dlpi: %s missing or bad unit number\n", __LINE__, iface);


   if (*iface == '/')
      strlcpy(dname, iface, sizeof(dname));
   else
      snprintf(dname, sizeof(dname), "%s/%s", DLPI_DEV_PREFIX, iface);

   /* Try device without unit number */
   strlcpy(dname2, dname, sizeof(dname2));
   cp = strchr(dname, *cp);
   *cp = '\0';
   if ((fd = open(dname, O_RDWR)) < 0)
   {
      if (errno != ENOENT)
         Error_msg("ec_inet_solaris:%d open() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

      /* Try again with unit number */
      if ((fd = open(dname2, O_RDWR)) < 0)
         Error_msg("ec_inet_solaris:%d open() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

      /* XXX Assume unit zero */
      ppa = 0;
   }
#endif

   /*
   ** Attach if "style 2" provider
   */
   if (dlinforeq(fd, ebuf) < 0 || dlinfoack(fd, (char *)buf, ebuf) < 0)
      Error_msg("ec_inet_solaris:%d dlinforeq() || dlinfoack() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   infop = &((union DL_primitives *)buf)->info_ack;
   if (infop->dl_provider_style == DL_STYLE2 && (dlattachreq(fd, ppa, ebuf) < 0 ||
       dlokack(fd, "attach", (char *)buf, ebuf) < 0))
      Error_msg("ec_inet_solaris:%d dlattachreq() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   /*
   ** Bind
   */
   if (dlbindreq(fd, 0, ebuf) < 0 || dlbindack(fd, (char *)buf, ebuf) < 0)
      Error_msg("ec_inet_solaris:%d dlbindreq() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));


   /*
   ** Determine link type
   */
   if (dlinforeq(fd, ebuf) < 0 || dlinfoack(fd, (char *)buf, ebuf) < 0)
      Error_msg("ec_inet_solaris:%d dlinforeq() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   infop = &((union DL_primitives *)buf)->info_ack;
   switch (infop->dl_mac_type)
   {
      case DL_CSMACD:
      case DL_ETHER:
         offset = 2;
         break;

      default:
         Error_msg("Interface not supported ( only DLT_EN10MB) | %d", infop->dl_mac_type);
   }

#ifdef   DLIOCRAW
   /*
   ** This is a non standard SunOS hack to get the ethernet header.
   */
   if (strioctl(fd, DLIOCRAW, 0, NULL) < 0)
      Error_msg("ec_inet_solaris:%d strioctl(DLIOCRAW) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

#endif

#ifdef HAVE_SYS_BUFMOD_H
   /*
   ** Another non standard call to get the data nicely buffered
   */
   if (ioctl(fd, I_PUSH, "bufmod") != 0)
      Error_msg("ec_inet_solaris:%d ioclt(I_PUSH) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   /*
   ** Now that the bufmod is pushed lets configure it.
   **
   ** There is a bug in bufmod(7). When dealing with messages of
   ** less than snaplen size it strips data from the beginning not
   ** the end.
   **
   ** This bug is supposed to be fixed in 5.3.2. Also, there is a
   ** patch available. Ask for bugid 1149065.
   */

   ss = MAXDLBUF;

   release = get_release(&osmajor, &osminor, &osmicro);
   if (osmajor == 5 && (osminor <= 2 || (osminor == 3 && osmicro < 2)) && getenv("BUFMOD_FIXED") == NULL)
   {
      fprintf(stderr, "WARNING: bufmod is broken in SunOS %s; ignoring snaplen.\n", release);
      ss = 0;
   }

   if (ss > 0 && strioctl(fd, SBIOCSSNAP, sizeof(ss), (char *)&ss) != 0)
      Error_msg("ec_inet_solaris:%d strioctl(SBIOCSSNAP) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   /*
   ** Set up the bufmod flags
   */
   if (strioctl(fd, SBIOCGFLAGS, sizeof(flag), (char *)&flag) < 0)
      Error_msg("ec_inet_solaris:%d strioctl(SBIOCGFLAGS) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   flag |= SB_NO_DROPS;
   if (strioctl(fd, SBIOCSFLAGS, sizeof(flag), (char *)&flag) != 0)
      Error_msg("ec_inet_solaris:%d strioctl(SBIOCSFLAGS) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

#endif

   /*
   ** As the last operation flush the read side.
   */
   if (ioctl(fd, I_FLUSH, FLUSHR) != 0)
      Error_msg("ec_inet_solaris:%d ioctl(I_FLUSH) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   bufsize = MAXDLBUF * sizeof(u_int);             // global var...

   fdprom = fd;   // for later use in the Set_Promisc

   return (fd);

}



int Inet_GetRawPacket(int sock, char *buffer, int MTU, short *type)
{
//    register int cc, n, caplen, origlen;
   register u_char *bp, *ep, *pk;
//    register struct bpf_insn *fcode;
   #ifdef HAVE_SYS_BUFMOD_H
      register struct sb_hdr *sbp;
      #ifdef LBL_ALIGN
         struct sb_hdr sbhdr;
      #endif
   #endif
//    int flags;
   struct strbuf data;
//    struct pcap_pkthdr pkthdr;
   int len = 0, pktlen = 0, caplen;
   char *buf;
   static char MyMAC[6]={0x65,0x74,0x74,0x65,0x72,0x63};


   if (SocketBuffer == -1)                   // only the first time
      SocketBuffer = Buffer_Create(1.0e5);   // 100 K buffer

   Buffer_Get(SocketBuffer, &pktlen, sizeof(u_int));
   len = Buffer_Get(SocketBuffer, buffer, pktlen );

   if (type != NULL)
   {
       if (!strncmp(MyMAC,"etterc",6))    // only the first time...
           Inet_GetIfaceInfo(Options.netiface, NULL, MyMAC, NULL, NULL);
       if (!memcmp(MyMAC,buffer,6))
           *type = 0; // PACKET_HOST
       else
           *type = 1; // !PACKET_HOST
   }

   if (len > 0) return len;                     // there was pending fata.

   buf = (u_char *)calloc(bufsize + offset, sizeof(char));     // buffer is global

// flags = 0;
// cc = p->cc;
// if (cc == 0) {
   data.buf = (char *)buf + offset;
   data.maxlen = MAXDLBUF;
   data.len = 0;
//    do {
//       if (getmsg(sock, &ctl, &data, &flags) < 0)
   getmsg(sock, &ctl, &data, 0);
//       {
//          /* Don't choke when we get ptraced */
//          if (errno == EINTR) {
//             cc = 0;
//             continue;
//          }
//          strlcpy(p->errbuf, pcap_strerror(errno), sizeof(p->errbuf));
//          return (-1);
//       }
//       cc = data.len;
//    } while (cc == 0);
//    bp = p->buffer + p->offset;
// } else
//    bp = p->bp;

   bp = buf + offset;

 /* Loop through packets */
// fcode = p->fcode.bf_insns;
// ep = bp + cc;
   ep = bp + data.len;
//    n = 0;

#ifdef HAVE_SYS_BUFMOD_H
   while (bp < ep)
   {
   #ifdef LBL_ALIGN
      if ((long)bp & 3)
      {
         sbp = &sbhdr;
         memcpy(sbp, bp, sizeof(*sbp));
      }
      else
   #endif
         sbp = (struct sb_hdr *)bp;

//    p->md.stat.ps_drop += sbp->sbh_drops;
      pk = bp + sizeof(*sbp);
      bp += sbp->sbh_totlen;
//       origlen = sbp->sbh_origlen;
      caplen = sbp->sbh_msglen;
#else
//       origlen = data.len;
      caplen = min(MAXDLBUF, data.len);
      pk = bp;
      bp += caplen;
#endif
//    ++p->md.stat.ps_recv;
//       if (bpf_filter(fcode, pk, origlen, caplen))
//       {
//          pkthdr.len = origlen;
//          pkthdr.caplen = caplen;
//          /* Insure caplen does not exceed snapshot */
//          if (pkthdr.caplen > MAXDLBUF)
//             pkthdr.caplen = MAXDLBUF;
//
//          (*callback)(user, &pkthdr, pk);

         Buffer_Put(SocketBuffer, &caplen, sizeof(u_int) );
         Buffer_Put(SocketBuffer, pk, caplen );

//          if (++n >= cnt && cnt >= 0)
//          {
//             p->cc = ep - bp;
//             p->bp = bp;
//             return (n);
//          }
//       }
#ifdef HAVE_SYS_BUFMOD_H
   }
#endif
//    p->cc = 0;
//    return (n);

   Buffer_Get(SocketBuffer, &pktlen, sizeof(u_int));
   len = Buffer_Get(SocketBuffer, buffer, pktlen );

   if (type != NULL)
   {
      if (!memcmp(MyMAC,buffer,6))
         *type = 0; // PACKET_HOST
      else
         *type = 1; // !PACKET_HOST
   }

   free(buf);
   return len;
}



int Inet_SendRawPacket(int sock, char *buffer, int len)
{
   struct  EnetHeaderInfo
   {
      struct ether_addr   DestEtherAddr;
      u_short             EtherFrameType;
   };

   struct EnetHeaderInfo ArpHeader = { {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, ETH_P_ARP };

   struct strbuf data, ctl;
   union DL_primitives *dlp;
   int c;
   struct EnetHeaderInfo *EnetHeaderInfoP;

   dlp = (union DL_primitives*) ctlbuf;
   dlp->unitdata_req.dl_primitive        = DL_UNITDATA_REQ;
   dlp->unitdata_req.dl_priority.dl_min  = 0;
   dlp->unitdata_req.dl_priority.dl_max  = 0;
   dlp->unitdata_req.dl_dest_addr_length = (sizeof(struct ether_addr) + sizeof(u_short));
   dlp->unitdata_req.dl_dest_addr_offset = DL_UNITDATA_REQ_SIZE;

   EnetHeaderInfoP = (struct EnetHeaderInfo *)(ctlbuf + DL_UNITDATA_REQ_SIZE);
   memcpy(EnetHeaderInfoP, (char *)&(ArpHeader), (sizeof(struct ether_addr) + sizeof(u_short)));

   /* Send it */
   ctl.len = DL_UNITDATA_REQ_SIZE + sizeof (struct EnetHeaderInfo);
   ctl.buf = (char *)dlp;

   data.maxlen = len;
   data.len    = len;
   data.buf    = buffer;

   c = putmsg(sock, NULL, &data, 0);
   if (c == -1)
      Error_msg("ec_inet_solaris:%d putmsg() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   return (len);

}



int Inet_SetPromisc(char *iface)
{
   int fd = fdprom;  // fdprom is global and set by Inet_OpenRawSock. it is the last opened socket
   u_long buf[MAXDLBUF];

   /*
   ** Enable promiscuous
   */
   if (dlpromisconreq(fd, DL_PROMISC_PHYS, ebuf) < 0 || dlokack(fd, "promisc_phys", (char *)buf, ebuf) < 0)
      Error_msg("ec_inet_solaris:%d dlpromisconreq() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   return 0;
}



void Inet_Restore_ifr(void)
{

   // this function is not needed !!
   // when a dlpi is closed, the interface is restored

}



void Inet_DisableForwarding(void)
{
   Error_msg("SOLARIS PORTING NOT YET FINISHED...\n");
}



void Inet_RestoreForwarding(void)
{
   Error_msg("SOLARIS PORTING NOT YET FINISHED...\n");
}


char *Inet_MacFromIP(unsigned long ip)
{
   Error_msg("SOLARIS PORTING NOT YET FINISHED...\n");
   return "";
}


/*
 *
 *    *** DLPI FUNCTIONS ***
 */

static int
send_request(int fd, char *ptr, int len, char *what, char *ebuf)
{
   struct strbuf ctl;
	int flags;

   ctl.maxlen = 0;
   ctl.len = len;
   ctl.buf = ptr;

	flags = 0;

   if (putmsg(fd, &ctl, (struct strbuf *) NULL, flags) < 0)
   {
      sprintf(ebuf, "send_request: putmsg \"%s\": %s", what, strerror(errno));
      return (-1);
   }
   return (0);
}

static int
recv_ack(int fd, int size, const char *what, char *bufp, char *ebuf)
{
    union DL_primitives *dlp;
    struct strbuf ctl;
    int flags;

    ctl.maxlen = MAXDLBUF;
    ctl.len = 0;
    ctl.buf = bufp;

    flags = 0;
    if (getmsg(fd, &ctl, (struct strbuf*)NULL, &flags) < 0)
    {
        sprintf(ebuf, "recv_ack: %s getmsg: %s", what, strerror(errno));
        return (-1);
    }

    dlp = (union DL_primitives *)ctl.buf;
    switch (dlp->dl_primitive)
    {
        case DL_INFO_ACK:
        case DL_PHYS_ADDR_ACK:
        case DL_BIND_ACK:
        case DL_OK_ACK:
#ifdef DL_HP_PPA_ACK
        case DL_HP_PPA_ACK:
#endif
        /*
         *  These are OK
         */
        break;

        case DL_ERROR_ACK:
            switch (dlp->error_ack.dl_errno)
            {
                case DL_BADPPA:
                    sprintf(ebuf, "recv_ack: %s bad ppa (device unit)", what);
                    break;
                case DL_SYSERR:
                    sprintf(ebuf, "recv_ack: %s: %s", what, strerror(dlp->error_ack.dl_unix_errno));
                    break;
                case DL_UNSUPPORTED:
                    sprintf(ebuf, "recv_ack: %s: Service not supplied by provider", what);
                    break;
                default:
                    sprintf(ebuf, "recv_ack: %s error 0x%x", what, (u_int)dlp->error_ack.dl_errno);
                    break;
            }
            return (-1);

        default:
            sprintf(ebuf, "recv_ack: %s unexpected primitive ack 0x%x ", what, (u_int)dlp->dl_primitive);
            return (-1);
    }

    if (ctl.len < size)
    {
        sprintf(ebuf, "recv_ack: %s ack too small (%d < %d)", what, ctl.len, size);
        return (-1);
    }
    return (ctl.len);
}

/*
static int
dlpromiscoffreq(int fd, u_int level, char *ebuf)
{
    dl_promiscon_req_t req;

    req.dl_primitive = DL_PROMISCOFF_REQ;
    req.dl_level     = level;

    return (send_request(fd, (char *)&req, sizeof(req), "promiscoff", ebuf));
}
*/

static int
dlpromisconreq(int fd, u_int level, char *ebuf)
{
    dl_promiscon_req_t req;

    req.dl_primitive = DL_PROMISCON_REQ;
    req.dl_level     = level;

    return (send_request(fd, (char *)&req, sizeof(req), "promiscon", ebuf));
}


static int
dlattachreq(int fd, u_int ppa, char *ebuf)
{
    dl_attach_req_t req;

    req.dl_primitive = DL_ATTACH_REQ;
    req.dl_ppa       = ppa;

    return (send_request(fd, (char *)&req, sizeof(req), "attach", ebuf));
}

static int
dlbindreq(int fd, u_int sap, char *ebuf)
{

    dl_bind_req_t req;

    memset((char *)&req, 0, sizeof(req));
    req.dl_primitive = DL_BIND_REQ;
#ifdef DL_HP_RAWDLS
    req.dl_max_conind = 1;  /* XXX magic number */
    /*
     *  22 is INSAP as per the HP-UX DLPI Programmer's Guide
     */
    req.dl_sap = 22;
    req.dl_service_mode = DL_HP_RAWDLS;
#else
    req.dl_sap = sap;
#ifdef DL_CLDLS
    req.dl_service_mode = DL_CLDLS;
#endif
#endif
    return (send_request(fd, (char *)&req, sizeof(req), "bind", ebuf));
}


static int
dlbindack(int fd, char *bufp, char *ebuf)
{
    return (recv_ack(fd, DL_BIND_ACK_SIZE, "bind", bufp, ebuf));
}


static int
dlokack(int fd, const char *what, char *bufp, char *ebuf)
{
    return (recv_ack(fd, DL_OK_ACK_SIZE, what, bufp, ebuf));
}


static int
dlinforeq(int fd, char *ebuf)
{
    dl_info_req_t req;

    req.dl_primitive = DL_INFO_REQ;

    return (send_request(fd, (char *)&req, sizeof(req), "info", ebuf));
}

static int
dlinfoack(int fd, char *bufp, char *ebuf)
{
    return (recv_ack(fd, DL_INFO_ACK_SIZE, "info", bufp, ebuf));
}

#ifdef HAVE_SYS_BUFMOD_H
static int
strioctl(int fd, int cmd, int len, char *dp)
{
   struct strioctl str;
   int rc;

   str.ic_cmd = cmd;
   str.ic_timout = -1;
   str.ic_len = len;
   str.ic_dp = dp;
   rc = ioctl(fd, I_STR, &str);

   if (rc < 0)
      return (rc);
   else
      return (str.ic_len);
}

static char *
get_release(u_int *majorp, u_int *minorp, u_int *microp)
{
   char *cp;
   static char buf[32];

   *majorp = 0;
   *minorp = 0;
   *microp = 0;
   if (sysinfo(SI_RELEASE, buf, sizeof(buf)) < 0)
      return ("?");
   cp = buf;
   if (!isdigit((int)*cp))
      return (buf);
   *majorp = strtol(cp, &cp, 10);
   if (*cp++ != '.')
      return (buf);
   *minorp =  strtol(cp, &cp, 10);
   if (*cp++ != '.')
      return (buf);
   *microp =  strtol(cp, &cp, 10);
   return (buf);
}
#endif


static char *
split_dname(char *device, int *unitp)
{
	char *cp;
	char *eos;
	int unit;

	/*
	 * Look for a number at the end of the device name string.
	 */
	cp = device + strlen(device) - 1;

#ifdef DEBUG
	Debug_msg("split_dname --> [%s] [%c]", device, *cp);
#endif

	if (*cp < '0' || *cp > '9')
		return (NULL);


	/* Digits at end of string are unit number */
	while (cp-1 >= device && *(cp-1) >= '0' && *(cp-1) <= '9')
		cp--;

	unit = strtol(cp, &eos, 10);
	if (*eos != '\0')
		return (NULL);

	*unitp = unit;
	return (cp);
}



/* EOF */
