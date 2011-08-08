/*
    ettercap -- inet utilities -- Module for MacOsX darwin 1.[34]
                                                    darwin 5.[01]

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

    $Id: ec_inet_macosx.c,v 1.7 2002/02/11 01:15:48 alor Exp $
*/


// This file is included from ../ec_inet.c


#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/timeb.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/time.h>
#include <net/bpf.h>

#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/if_types.h>
#include <arpa/inet.h>

#include <netinet/if_ether.h>
#ifdef HAVE_NET_ETHERNET_H
   #include <net/ethernet.h>
#endif


int fdprom;
int size;
int SocketBuffer = -1;


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
      Error_msg("ec_inet_macosx:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   buf_size = 8192;

   for (;;) {
      buf = malloc (buf_size);
      if (buf == NULL)
         Error_msg("ec_inet_macosx:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

      ifc.ifc_len = buf_size;
      ifc.ifc_buf = buf;
      memset (buf, 0, buf_size);
      if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0 && errno != EINVAL)
         Error_msg("ec_inet_macosx:%d ioctl(SIOCGIFCONF) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

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
         Error_msg("ec_inet_macosx:%d ioctl(SIOCGIFFLAGS) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
      }

#ifdef DEBUG
   Debug_msg("Inet_FindIFace -- check for [%s]", ifr.ifr_name);
#endif

      /* Must be up and not the loopback */
      if ((ifr.ifr_flags & IFF_UP) == 0 || (ifr.ifr_flags & IFF_LOOPBACK) != 0)
         continue;

      endcp = ifrp->ifr_name + strlen(ifrp->ifr_name);
      for (cp = ifrp->ifr_name; cp < endcp && !isdigit(*cp); ++cp)
         continue;

      if (isdigit (*cp)) {
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
      Error_msg("ec_inet_macosx:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

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
   int sock;
   struct ifreq ifr;

   sock = socket(PF_INET, SOCK_DGRAM, 0);

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
         *MTU = ifr.ifr_mtu;
   }

   if (MyMAC != NULL)
   {
      int mib[6];
      size_t len;
      char *buf, *next, *end;
      struct if_msghdr *ifm;
      struct sockaddr_dl *sdl;

      mib[0] = CTL_NET;
      mib[1] = AF_ROUTE;
      mib[2] = 0;
      mib[3] = AF_LINK;
      mib[4] = NET_RT_IFLIST;
      mib[5] = 0;

      if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
         Error_msg("ec_inet_macosx:%d sysctl() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

      if ((buf = (char *)malloc(len)) == NULL )
         Error_msg("ec_inet_macosx:%d malloc() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

      if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
         Error_msg("ec_inet_macosx:%d sysctl() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

      end = buf + len;

      for (next = buf ; next < end ; next += ifm->ifm_msglen)
      {
         ifm = (struct if_msghdr *)next;
         if (ifm->ifm_type == RTM_IFINFO)
         {
            sdl = (struct sockaddr_dl *)(ifm + 1);
            if (strncmp(&sdl->sdl_data[0], iface, sdl->sdl_nlen) == 0)
            {
                memcpy(MyMAC, LLADDR(sdl), ETHER_ADDR_LEN);
                break;
            }
         }
      }

      free(buf);
   }

   if (IP != NULL)
   {
      if ( ioctl(sock, SIOCGIFADDR, &ifr) < 0 )
         Error_msg("ec_inet_macosx:%d ioctl(SIOCGIFADDR) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
      memcpy((char *)IP, ifr.ifr_addr.sa_data+2, 4);
   }

   if (NetMask != NULL)
   {
      if ( ioctl(sock, SIOCGIFNETMASK, &ifr) < 0 )
         Error_msg("ec_inet_macosx:%d ioctl(SIOCGIFNETMASK) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
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




int Inet_OpenRawSock(char *iface)
{
   int fd, i = 0, type;
   char device[sizeof "/dev/bpf0000"];
   struct bpf_version bv;
   struct ifreq ifr;
   char MyMAC[6];

   // this BPF will ignore all outgoing packets

   static struct bpf_insn insns[] = {
      BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 6),           // load mac address [1][2]
      BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 0, 4), // k is left 0x00 and will be set later... insns[1].k = htons(*(short *)MyMAC);
      BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 8),           // load mac address [3][4]
      BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 0, 2), // if equal check the third part, else jump 2
      BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 10),          // load mac address [5][6]
      BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 1, 0), // if equal this is outgoing ! drop it !
      BPF_STMT(BPF_RET|BPF_K, (u_int)-1),          // no filter, passing the wole packet
      BPF_STMT(BPF_RET|BPF_K, 0),                  // ignore the packet
   };

   static struct bpf_program filter = {
      sizeof insns / sizeof(insns[0]),
      insns
   };

#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)
    u_int spoof_eth_src = 1;
#endif

   Inet_GetIfaceInfo(iface, NULL, MyMAC, NULL, NULL);

   insns[1].k = htons(*(short *)MyMAC);         // put MyMac in the filter...
   insns[3].k = htons(*(short *)(MyMAC+2));
   insns[5].k = htons(*(short *)(MyMAC+4));


#ifdef DEBUG
   Debug_msg("Inet_OpenRawSock %s", iface);
#endif


   do    // find an available bpf device
   {
      sprintf(device, "/dev/bpf%d", i++);
      fd = open(device, O_RDWR);
   } while (fd < 0 && errno == EBUSY);

   if (fd < 0)
      Error_msg("ec_inet_macosx:%d  no /dev/bpf* available (tried to open %d) | ERRNO : %d | %s", __LINE__, i, errno, strerror(errno));

#ifdef DEBUG
   Debug_msg("Inet_OpenRawSock \t fd = %d -- /dev/bpf%d ", fd, i-1);
#endif

   if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0)      // get bpf version
      Error_msg("ec_inet_macosx:%d  ioctl(BIOCVERSION) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   if (bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION)
      Error_msg(" Kernel bpf filter out of date ");

   for (size = 32768; size != 0; size >>= 1)
   {
      ioctl(fd, BIOCSBLEN, (caddr_t)&size);

      strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));    // attach the iface to the bpf
      if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) >= 0)
         break;  /* that size worked; we're done */

      if (errno != ENOBUFS)
         Error_msg("ec_inet_macosx:%d  ioctl(BIOCSETIF) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
   }

   if (size == 0) Error_msg("BIOCSBLEN: No buffer size worked");

   if (ioctl(fd, BIOCGBLEN, (caddr_t)&size) < 0)
     Error_msg("ec_inet_macosx:%d  ioctl(BIOCGBLEN) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if (ioctl(fd, BIOCGDLT, (caddr_t)&type) == -1)           // Get the data link layer type.
      Error_msg("ec_inet_macosx:%d  ioctl(BIOCGDLT) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if (type != DLT_EN10MB)
      Error_msg("Interface not supported ( only DLT_EN10MB) | %d", type);

#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)     // auto fill the source mac address now set OFF
    if (ioctl(fd, BIOCSHDRCMPLT, &spoof_eth_src) == -1)
      Error_msg("ec_inet_macosx:%d  ioctl(BIOCSHDRCMPLT) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
#endif

   i = 1;
   if (ioctl(fd, BIOCIMMEDIATE, &i) < 0)                    // Set immediate mode so packets are processed as they arrive.
      Error_msg("ec_inet_macosx:%d  ioctl(BIOCIMMEDIATE) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   if (ioctl(fd, BIOCSETF, (caddr_t)&filter) < 0)           // Set filter program.
      Error_msg("ec_inet_macosx:%d  ioctl(BIOCSETF) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   fdprom = fd;

   return fd;

}



int Inet_GetRawPacket(int sock, char *buffer, int MTU, short *type)
{
   int len = 0, pktlen = 0;
   u_char *buf, *bp, *ep;
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

   buf = (char *)calloc(size, sizeof(char));    // size is global and set by BIOCGBLEN

   len = read(sock, buf, size);


#define bhp ((struct bpf_hdr *)bp)              // Loop through the packet(s)
         bp = buf;
         ep = bp + len;
         while (bp < ep) {
            u_int caplen, hdrlen;

            caplen = bhp->bh_caplen;
            hdrlen = bhp->bh_hdrlen;

//          //  bp + hdrlen is my packet
//          //  caplen is the length

            if (caplen > MTU + ETH_HEADER) caplen = MTU + ETH_HEADER;  // evil workaround for the 1518 size packet with FCS

            Buffer_Put(SocketBuffer, &caplen, sizeof(u_int) );
            Buffer_Put(SocketBuffer, bp + hdrlen, caplen );

            bp += BPF_WORDALIGN(hdrlen + caplen);
         }
#undef bhp

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

   int sent;

   sent = write(sock, buffer, len);
   if (sent < len)
   {
      while (errno == ENOBUFS)
      {
         usleep(5000);
         sent = write(sock, buffer, len);
         if (sent == len) return (sent);
      }

      Error_msg("ec_inet_macosx:%d write() %d(%d) | ERRNO : %d | %s \n", __LINE__, len, sent, errno, strerror(errno));
   }

   return (sent);
}



int Inet_SetPromisc(char *iface)
{

#ifdef DEBUG
   Debug_msg("Inet_SetPromisc %s %d", iface, fdprom);
#endif

   if ( ioctl(fdprom, BIOCPROMISC, NULL) < 0 )
      Error_msg("ec_inet_macosx:%d ioctl(BIOCPROMISC) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   return 0;
}



void Inet_Restore_ifr(void)
{

   // this function is not needed !!
   // when a bpf is closed, the interface is restored

}



void Inet_DisableForwarding(void)
{

   int mib[4];      // for sysctl()
   int val = 0;     // for sysctl()   disable
   size_t len;

   mib[0] = CTL_NET;
   mib[1] = PF_INET;
   mib[2] = IPPROTO_IP;
   mib[3] = IPCTL_FORWARDING;

   len = sizeof(IpForward_status);

   if( (sysctl(mib, 4, &IpForward_status, &len, &val, sizeof(val))) == -1)
    Error_msg("ec_inet_macosx:%d sysctl() | net.inet.ip.forwarding | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

#ifdef DEBUG
   Debug_msg("Inet_DisableForwarding | net.inet.ip.forwarding = %d  old_value = %d\n", val, IpForward_status);
#endif

   atexit(Inet_RestoreForwarding);

}



void Inet_RestoreForwarding(void)
{

   int mib[4];      // for sysctl()

   mib[0] = CTL_NET;
   mib[1] = PF_INET;
   mib[2] = IPPROTO_IP;
   mib[3] = IPCTL_FORWARDING;

   if (strcmp(ECThread_getname(pthread_self()), PROGRAM)) return;

   if( (sysctl(mib, 4, NULL, NULL, &IpForward_status, sizeof(IpForward_status))) == -1)
      Error_msg("ec_inet_macosx:%d sysctl() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

#ifdef DEBUG
   Debug_msg("Inet_RestoreForwarding | net.inet.ip.forwarding = %d\n", IpForward_status);
#endif


}


char *Inet_MacFromIP(unsigned long ip)
{
   int mib[6];
   size_t len;
   char *buf, *next, *end;
   struct rt_msghdr *rtm;
   struct sockaddr_inarp *sin;
   struct sockaddr_dl *sdl;
   static char ETH_BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

#ifdef DEBUG
   Debug_msg("Inet_MacFromIP");
#endif

   mib[0] = CTL_NET;
   mib[1] = AF_ROUTE;
   mib[2] = 0;
   mib[3] = AF_INET;
   mib[4] = NET_RT_FLAGS;
   mib[5] = RTF_LLINFO;

   if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
      Error_msg("ec_inet_macosx:%d sysctl() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if ((buf = (char *)malloc(len)) == NULL)
      Error_msg("ec_inet_macosx:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
   {
      free(buf);
      Error_msg("ec_inet_macosx:%d sysctl() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
   }
   end = buf + len;

   for (next = buf ; next < end ; next += rtm->rtm_msglen)
   {
      rtm = (struct rt_msghdr *)next;
      sin = (struct sockaddr_inarp *)(rtm + 1);
      sdl = (struct sockaddr_dl *)(sin + 1);

      if (sin->sin_addr.s_addr == ip && sdl->sdl_alen)
      {
         free(buf);
         return LLADDR(sdl);
      }
      else     // not in cache... try to find it...
      {
         u_char *buf;
         char MyMAC[6];
         u_long MyIP;
         int MTU, sock;
         TIME_DECLARE;

#ifdef DEBUG
   Debug_msg("Inet_MacFromIP -- try to find it");
#endif

         sock = Inet_OpenRawSock(Options.netiface);

         Inet_GetIfaceInfo(Options.netiface, &MTU, MyMAC, &MyIP, NULL);

         if (ip == MyIP)
         {
            #ifdef DEBUG
               Debug_msg("Inet_MacFromIP -- try to find me... ;)");
            #endif
            memcpy(LLADDR(sdl), MyMAC, ETHER_ADDR_LEN);
            Inet_CloseRawSock(sock);
            return (char *) LLADDR(sdl);
         }

         buf = Inet_Forge_packet( ETH_HEADER + ARP_HEADER );
         Inet_Forge_ethernet( buf, MyMAC, ETH_BROADCAST, ETH_P_ARP );

         Inet_Forge_arp( buf+ETH_HEADER, ARPOP_REQUEST,
                         MyMAC, MyIP,
                         ARP_BROADCAST, ip );

         Inet_SendRawPacket(sock, buf, ETH_HEADER + ARP_HEADER);
         Inet_Forge_packet_destroy( buf );
         buf = Inet_Forge_packet( MTU );

         fcntl(sock, F_SETFL, O_NONBLOCK);
         TIME_START;

         do
         {
            int len;
            short pkttype;
            ETH_header *ethpkt;
            ARP_header *arppkt;

            len = Inet_GetRawPacket(sock, buf, MTU, &pkttype);

            ethpkt = (ETH_header *)buf;
            arppkt = (ARP_header *)(buf + ETH_HEADER);

            TIME_FINISH;

            if (len > 0 && pkttype == PACKET_HOST && ethpkt->type == htons(ETH_P_ARP) && arppkt->opcode == htons(ARPOP_REPLY))
            {
               if ( *(unsigned long *)arppkt->source_ip == ip )
               {
                  memcpy(LLADDR(sdl), &arppkt->source_add, ETHER_ADDR_LEN);
                  Inet_Forge_packet_destroy( buf );
                  Inet_CloseRawSock(sock);
                  return (char *) LLADDR(sdl);
               }
            }
         } while ( TIME_ELAPSED < 0.5 );
         Inet_CloseRawSock(sock);
      }
   }
   free(buf);

   return ETH_BROADCAST;  // workaround for non local ip

}


/* EOF */
