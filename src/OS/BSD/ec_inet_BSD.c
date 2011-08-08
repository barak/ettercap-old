/*
    ettercap -- inet utilities -- Module for FreeBSD 4.x
                                             OpenBSD 2.[789]
                                             NetBSD 1.5

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

    $Id: ec_inet_BSD.c,v 1.9 2002/02/11 01:15:48 alor Exp $
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

#ifdef HAVE_IFADDRS_H
   #include <ifaddrs.h>
#endif
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


int Inet_FindIFace(char *iface)
{
#ifdef HAVE_GETIFADDRS
   struct ifaddrs *ifalist, *ifa, *ifp = NULL;

   if (getifaddrs(&ifalist) != 0)
      Error_msg("ec_inet_BSD:%d  getifaddrs() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   for (ifa = ifalist; ifa; ifa = ifa->ifa_next)
   {
      if ((ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_LOOPBACK) || !strncmp(ifa->ifa_name, "pflog", 5))
         continue;

      ifp = ifa;
   }

   if (ifp == NULL)  // no device found
   {
      free(ifalist);
      return -1;
   }

   strlcpy(iface, ifp->ifa_name, sizeof(Options.netiface));

#ifdef DEBUG
   Debug_msg("Inet_FindIFace -- %s found !!", iface);
#endif

   free(ifalist);
   return 0;

#else  // don't have getifaddrs

// adapded from pcap_lookupdev

   int fd, minunit, n;
   char *cp;
   struct ifreq *ifrp, *ifend, *ifnext, *mp;
   struct ifconf ifc;
   char *buf;
   struct ifreq ifr;
   unsigned int buf_size;

   fd = socket(AF_INET, SOCK_DGRAM, 0);
   if (fd < 0)
      Error_msg("ec_inet_BSD:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   buf_size = 8192;

   for (;;) {
      buf = malloc (buf_size);
      if (buf == NULL)
         Error_msg("ec_inet_BSD:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

      ifc.ifc_len = buf_size;
      ifc.ifc_buf = buf;
      memset (buf, 0, buf_size);
      if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0 && errno != EINVAL)
         Error_msg("ec_inet_BSD:%d ioctl(SIOCGIFCONF) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

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
         Error_msg("ec_inet_BSD:%d ioctl(SIOCGIFFLAGS) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
      }

#ifdef DEBUG
   Debug_msg("Inet_FindIFace -- check for [%s]", ifr.ifr_name);
#endif

      /* Must be up and not the loopback */
      if ((ifr.ifr_flags & IFF_UP) == 0 || (ifr.ifr_flags & IFF_LOOPBACK) != 0  || !strncmp(ifr.ifa_name, "pflog", 5))
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

#endif
}



int Inet_CorrectIface(char *iface)
{
#ifdef HAVE_GETIFADDRS
   struct ifaddrs *ifalist, *ifa;

#ifdef DEBUG
   Debug_msg("Inet_CorrectIface -- %s ", iface);
#endif

   if (getifaddrs(&ifalist) != 0)
      Error_msg("ec_inet_BSD:%d  getifaddrs() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   for (ifa = ifalist; ifa; ifa = ifa->ifa_next)
   {
      if ( (ifa->ifa_flags & IFF_UP) == 0 || (ifa->ifa_flags & IFF_LOOPBACK) != 0 || strcmp(iface, ifa->ifa_name) )
         continue;

      free(ifalist);
      return 0;
   }

   // no iface found !!

   free(ifalist);
   return -1;

#else // don't have getifaddrs

   int sock;
   struct ifreq ifr;

#ifdef DEBUG
   Debug_msg("Inet_CorrectIface\t\tIface: %s", iface);
#endif

   sock = socket(AF_INET, SOCK_DGRAM, 0);
   if (sock < 0)
      Error_msg("ec_inet_BSD:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

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
#endif
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
         //*MTU = ifr.ifr_ifru.ifru_mtu;
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
         Error_msg("ec_inet_BSD:%d sysctl() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

      if ((buf = (char *)malloc(len)) == NULL )
         Error_msg("ec_inet_BSD:%d malloc() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

      if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
         Error_msg("ec_inet_BSD:%d sysctl() | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

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
         Error_msg("ec_inet_BSD:%d ioctl(SIOCGIFADDR) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
      memcpy((char *)IP, ifr.ifr_addr.sa_data+2, 4);
   }

   if (NetMask != NULL)
   {
      if ( ioctl(sock, SIOCGIFNETMASK, &ifr) < 0 )
         Error_msg("ec_inet_BSD:%d ioctl(SIOCGIFNETMASK) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
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
      Error_msg("ec_inet_BSD:%d  no /dev/bpf* available (tried to open %d) | ERRNO : %d | %s", __LINE__, i, errno, strerror(errno));

#ifdef DEBUG
   Debug_msg("Inet_OpenRawSock \t fd = %d -- /dev/bpf%d ", fd, i-1);
#endif

   if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0)      // get bpf version
      Error_msg("ec_inet_BSD:%d  ioctl(BIOCVERSION) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   if (bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION)
      Error_msg(" Kernel bpf filter out of date ");

   for (size = 32768; size != 0; size >>= 1)
   {
      ioctl(fd, BIOCSBLEN, (caddr_t)&size);

      strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));    // attach the iface to the bpf
      if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) >= 0)
         break;  /* that size worked; we're done */

      if (errno != ENOBUFS)
         Error_msg("ec_inet_BSD:%d  ioctl(BIOCSETIF) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
   }

   if (size == 0) Error_msg("BIOCSBLEN: No buffer size worked");

   if (ioctl(fd, BIOCGBLEN, (caddr_t)&size) < 0)
     Error_msg("ec_inet_BSD:%d  ioctl(BIOCGBLEN) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if (ioctl(fd, BIOCGDLT, (caddr_t)&type) == -1)           // Get the data link layer type.
      Error_msg("ec_inet_BSD:%d  ioctl(BIOCGDLT) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if (type != DLT_EN10MB)
      Error_msg("Interface not supported ( only DLT_EN10MB) | %d", type);

#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT)     // auto fill the source mac address now set to OFF
    if (ioctl(fd, BIOCSHDRCMPLT, &spoof_eth_src) == -1)
      Error_msg("ec_inet_BSD:%d  ioctl(BIOCSHDRCMPLT) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
#endif

   i = 1;
   if (ioctl(fd, BIOCIMMEDIATE, &i) < 0)                    // Set immediate mode so packets are processed as they arrive.
      Error_msg("ec_inet_BSD:%d  ioctl(BIOCIMMEDIATE) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   if (ioctl(fd, BIOCSETF, (caddr_t)&filter) < 0)           // Set filter program.
      Error_msg("ec_inet_BSD:%d  ioctl(BIOCSETF) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   fdprom = fd;

   return fd;

}



int Inet_GetRawPacket(int sock, char *buffer, int MTU, short *type)
{
   int len = 0, pktlen = 0;
   u_char *buf, *bp, *ep;
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
           *type = PACKET_HOST;
       else
           *type = !PACKET_HOST;
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

      Error_msg("ec_inet_BSD:%d write() %d(%d) | ERRNO : %d | %s \n", __LINE__, len, sent, errno, strerror(errno));
   }

   return (sent);
}



int Inet_SetPromisc(char *iface)
{

#ifdef DEBUG
   Debug_msg("Inet_SetPromisc %s %d", iface, fdprom);
#endif

   if ( ioctl(fdprom, BIOCPROMISC, NULL) < 0 )
      Error_msg("ec_inet_BSD:%d ioctl(BIOCPROMISC) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

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
    Error_msg("ec_inet_BSD:%d sysctl() | net.inet.ip.forwarding | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

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
      Error_msg("ec_inet_BSD:%d sysctl() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

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
      Error_msg("ec_inet_BSD:%d sysctl() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if ((buf = (char *)malloc(len)) == NULL)
      Error_msg("ec_inet_BSD:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
   {
      free(buf);
      Error_msg("ec_inet_BSD:%d sysctl() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
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


#ifdef PERMIT_HTTPS


// ARP ENTRY MANAGEMENT ---------------------------  ripped form arp.c  ----------------


#define ROUNDUP(a)   ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static int pid;
static int s = -1;

struct   sockaddr_in so_mask = {8, 0, 0, { 0xffffffff}};
struct   sockaddr_inarp blank_sin = {sizeof(blank_sin), AF_INET }, sin_m;
struct   sockaddr_dl blank_sdl = {sizeof(blank_sdl), AF_LINK }, sdl_m;
struct   {
   struct   rt_msghdr m_rtm;
   char  m_space[512];
}  m_rtmsg;

u_long SavedIP;
u_char SavedMAC[6];

// protos...

int rtmsg_arp(int cmd);


//==================================

int rtmsg_arp(int cmd)
{
   static int seq;
   int rlen;
   register struct rt_msghdr *rtm = &m_rtmsg.m_rtm;
   register char *cp = m_rtmsg.m_space;
   register int l;

   errno = 0;
   if (cmd == RTM_DELETE)
      goto doit;
   bzero((char *)&m_rtmsg, sizeof(m_rtmsg));
   rtm->rtm_flags = 0;
   rtm->rtm_version = RTM_VERSION;

   switch (cmd) {
      case RTM_ADD:
         rtm->rtm_addrs |= RTA_GATEWAY;
         rtm->rtm_rmx.rmx_expire = 0;
         rtm->rtm_inits = RTV_EXPIRE;
         rtm->rtm_flags |= (RTF_HOST | RTF_STATIC);
         sin_m.sin_other = 0;
      case RTM_GET:
         rtm->rtm_addrs |= RTA_DST;
   }
#define NEXTADDR(w, s) \
   if (rtm->rtm_addrs & (w)) { \
      bcopy((char *)&s, cp, sizeof(s)); cp += ROUNDUP(sizeof(s));}

   NEXTADDR(RTA_DST, sin_m);
   NEXTADDR(RTA_GATEWAY, sdl_m);
   NEXTADDR(RTA_NETMASK, so_mask);

#undef NEXTADDR

   rtm->rtm_msglen = cp - (char *)&m_rtmsg;
doit:
   l = rtm->rtm_msglen;
   rtm->rtm_seq = ++seq;
   rtm->rtm_type = cmd;

   if ((rlen = write(s, (char *)&m_rtmsg, l)) < 0) {
      if (errno != ESRCH || cmd != RTM_DELETE)
         Error_msg("ec_inet_BSD:%d writing on PF_ROUTE socket | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
   }
   do {
      l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
   } while (l > 0 && (rtm->rtm_seq != seq || rtm->rtm_pid != pid));
   if (l < 0)
      Error_msg("ec_inet_BSD:%d reading on PF_ROUTE socket | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   return (0);
}



void Inet_UnSetARPEntry(void)
{
   register struct sockaddr_inarp *sin = &sin_m;
   register struct rt_msghdr *rtm = &m_rtmsg.m_rtm;
   struct sockaddr_dl *sdl;

#ifdef DEBUG
   Debug_msg("Inet_UnSetARPEntry");
#endif

   s = socket(PF_ROUTE, SOCK_RAW, 0);
   if (s < 0)
      Error_msg("ec_inet_BSD:%d socket(PF_ROUTE) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   sin_m = blank_sin;
   sin->sin_addr.s_addr = SavedIP;

   rtmsg_arp(RTM_GET);

   sin = (struct sockaddr_inarp *)(rtm + 1);
   sdl = (struct sockaddr_dl *)(ROUNDUP(sin->sin_len) + (char *)sin);

   rtmsg_arp(RTM_DELETE);

   close(s);
}



int Inet_SetARPEntry(unsigned long IP, char MAC[6])
{
   register struct sockaddr_inarp *sin = &sin_m;
   register struct sockaddr_dl *sdl;
   register struct rt_msghdr *rtm = &(m_rtmsg.m_rtm);
   u_char *ea;
   int ret;

#ifdef DEBUG
   Debug_msg("Inet_SetARPEntry");
#endif

   pid = getpid();

   s = socket(PF_ROUTE, SOCK_RAW, 0);
   if (s < 0)
      Error_msg("ec_inet_BSD:%d socket(PF_ROUTE) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   sdl_m = blank_sdl;
   sin_m = blank_sin;
   sin->sin_addr.s_addr = Inet_Fake_Host();

   ea = (u_char *)LLADDR(&sdl_m);
   memcpy(ea, MAC, 6);
   sdl_m.sdl_alen = 6;

   rtmsg_arp(RTM_GET);

   sin = (struct sockaddr_inarp *)(rtm + 1);
   sdl = (struct sockaddr_dl *)(ROUNDUP(sin->sin_len) + (char *)sin);

   sdl_m.sdl_type = sdl->sdl_type;
   sdl_m.sdl_index = sdl->sdl_index;

   SavedIP = Inet_Fake_Host();
   memcpy(SavedMAC, MAC, 6);

   atexit(Inet_UnSetARPEntry);

   ret = rtmsg_arp(RTM_ADD);

   close(s);

   return ret;

}



// ROUTE MANAGEMENT ---------------------------  ripped form route.c ----------------

int forcenet, forcehost, rtm_addrs, af, aflen = sizeof (struct sockaddr_in);
struct   rt_metrics rt_metrics;
u_long  rtm_inits;

union sockunion {
   struct   sockaddr sa;
   struct   sockaddr_in sin;
   struct   sockaddr_dl sdl;
} so_dst, so_gate, so_mask_r, so_genmask, so_ifa, so_ifp;

typedef union sockunion *sup;

// protos.....

int rtmsg_route(int cmd, int flags);
void inet_makenetandmask(u_long net, struct sockaddr_in *sin, u_long bits);
int getaddr(int which, char *s, struct hostent **hpp);
void mask_addr(void);
int rtmsg_route(int cmd, int flags);

//====================

void inet_makenetandmask(u_long net, struct sockaddr_in *sin, u_long bits)
{
   u_long addr, mask = 0;
   register char *cp;

   rtm_addrs |= RTA_NETMASK;
   if (bits) {
      addr = net;
      mask = 0xffffffff << (32 - bits);
   } else if (net == 0)
      mask = addr = 0;
   else if (net < 128) {
      addr = net << IN_CLASSA_NSHIFT;
      mask = IN_CLASSA_NET;
   } else if (net < 65536) {
      addr = net << IN_CLASSB_NSHIFT;
      mask = IN_CLASSB_NET;
   } else if (net < 16777216L) {
      addr = net << IN_CLASSC_NSHIFT;
      mask = IN_CLASSC_NET;
   } else {
      addr = net;
      if ((addr & IN_CLASSA_HOST) == 0)
         mask =  IN_CLASSA_NET;
      else if ((addr & IN_CLASSB_HOST) == 0)
         mask =  IN_CLASSB_NET;
      else if ((addr & IN_CLASSC_HOST) == 0)
         mask =  IN_CLASSC_NET;
      else
         mask = -1;
   }
   sin->sin_addr.s_addr = htonl(addr);
   sin = &so_mask_r.sin;
   sin->sin_addr.s_addr = htonl(mask);
   sin->sin_len = 0;
   sin->sin_family = 0;
   cp = (char *)(&sin->sin_addr + 1);
   while (*--cp == 0 && cp > (char *)sin)
      ;
   sin->sin_len = 1 + cp - (char *)sin;
}



int getaddr(int which, char *s, struct hostent **hpp)
{
   sup su;
   struct hostent *hp;
   struct netent *np;
   u_long val;
   int afamily;  /* local copy of af so we can change it */

   memset(&su, 0, sizeof(sup));

   if (af == 0) {
      af = AF_INET;
      aflen = sizeof(struct sockaddr_in);
   }
   afamily = af;
   rtm_addrs |= which;
   switch (which) {
   case RTA_DST:
      su = &so_dst;
      break;
   case RTA_GATEWAY:
      su = &so_gate;
      break;
   case RTA_NETMASK:
      su = &so_mask_r;
      break;
   }

   su->sa.sa_len = aflen;
   su->sa.sa_family = afamily; /* cases that don't want it have left already */

   if (hpp == NULL)
      hpp = &hp;
   *hpp = NULL;

   if ((which != RTA_DST || forcenet == 0) && (val = inet_addr(s)) != INADDR_NONE) {
      su->sin.sin_addr.s_addr = val;
      if (which != RTA_DST || inet_lnaof(su->sin.sin_addr) != INADDR_ANY)
         return (1);
      else {
         val = ntohl(val);
         goto netdone;
      }
   }

   if (which == RTA_DST && forcehost == 0 && ((val = inet_network(s)) != INADDR_NONE ||
       ((np = getnetbyname(s)) != NULL && (val = np->n_net) != 0))) {
netdone:
      inet_makenetandmask(val, &su->sin, 0);
      return (0);
   }

   hp = gethostbyname(s);
   if (hp) {
      *hpp = hp;
      su->sin.sin_family = hp->h_addrtype;
      bcopy(hp->h_addr, (char *)&su->sin.sin_addr,
          MIN(hp->h_length, sizeof(su->sin.sin_addr)));
      return (1);
   }
   Error_msg("ec_inet_BSD:%d bad address %s | ERRNO : %d | %s", __LINE__, s, errno, strerror(errno));
   return 0;
}

void mask_addr()
{
   int olen = so_mask_r.sa.sa_len;
   register char *cp1 = olen + (char *)&so_mask_r, *cp2;

   for (so_mask_r.sa.sa_len = 0; cp1 > (char *)&so_mask_r; )
      if (*--cp1 != 0) {
         so_mask_r.sa.sa_len = 1 + cp1 - (char *)&so_mask_r;
         break;
      }
   if ((rtm_addrs & RTA_DST) == 0)
      return;

   switch (so_dst.sa.sa_family) {
   case AF_INET:
   case AF_APPLETALK:
   case 0:
      return;
   }
   cp1 = so_mask_r.sa.sa_len + 1 + (char *)&so_dst;
   cp2 = so_dst.sa.sa_len + 1 + (char *)&so_dst;
   while (cp2 > cp1)
      *--cp2 = 0;
   cp2 = so_mask_r.sa.sa_len + 1 + (char *)&so_mask_r;
   while (cp1 > so_dst.sa.sa_data)
      *--cp1 &= *--cp2;
}


int rtmsg_route(int cmd, int flags)
{
   static int seq;
   int rlen;
   register char *cp = m_rtmsg.m_space;
   register int l;

#define NEXTADDR(w, u) \
   if (rtm_addrs & (w)) {\
       l = ROUNDUP(u.sa.sa_len); bcopy((char *)&(u), cp, l); cp += l;\
   }

   errno = 0;
   bzero((char *)&m_rtmsg, sizeof(m_rtmsg));
   if (cmd == 'a')
      cmd = RTM_ADD;
   else
      cmd = RTM_DELETE;

#define rtm m_rtmsg.m_rtm
   rtm.rtm_type = cmd;
   rtm.rtm_flags = flags;
   rtm.rtm_version = RTM_VERSION;
   rtm.rtm_seq = ++seq;
   rtm.rtm_addrs = rtm_addrs;
   rtm.rtm_rmx = rt_metrics;
   rtm.rtm_inits = rtm_inits;

   if (rtm_addrs & RTA_NETMASK)
      mask_addr();
   NEXTADDR(RTA_DST, so_dst);
   NEXTADDR(RTA_GATEWAY, so_gate);
   NEXTADDR(RTA_NETMASK, so_mask_r);
   NEXTADDR(RTA_GENMASK, so_genmask);
   NEXTADDR(RTA_IFP, so_ifp);
   NEXTADDR(RTA_IFA, so_ifa);
   rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;
   if ((rlen = write(s, (char *)&m_rtmsg, l)) < 0)
      Error_msg("ec_inet_BSD:%d writing to routing socket | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

#undef rtm
#undef NEXTADDR
   return (0);
}



void Inet_UnsetRoute(void)
{
   int flags = RTF_STATIC;
   struct hostent *hp = 0;
   int IP;

#ifdef DEBUG
   Debug_msg("Inet_UnsetRoute");
#endif

   pid = getpid();

   s = socket(PF_ROUTE, SOCK_RAW, 0);
   if (s < 0)
      Error_msg("ec_inet_BSD:%d socket(PF_ROUTE) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   forcehost = 0;
   forcenet++;
   hp = 0;
   flags = RTF_STATIC;

   IP = Inet_Fake_Host();

   getaddr(RTA_DST, "1.0.0.0", &hp);
   getaddr(RTA_GATEWAY, int_ntoa(IP), &hp);
   getaddr(RTA_NETMASK, "255.0.0.0", 0);

   flags |= RTF_UP;
   flags |= RTF_GATEWAY;

   rtmsg_route('d', flags);

   forcenet = 0;

   close(s);
}



void Inet_SetRoute(void)
{
   int flags = RTF_STATIC;
   struct hostent *hp = 0;
   int IP;

#ifdef DEBUG
   Debug_msg("Inet_SetRoute NET");
#endif

   pid = getpid();

   s = socket(PF_ROUTE, SOCK_RAW, 0);
   if (s < 0)
      Error_msg("ec_inet_BSD:%d socket(PF_ROUTE) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));


   forcehost = 0;
   forcenet++;
   hp = 0;
   flags = RTF_STATIC;

   IP = Inet_Fake_Host();

   getaddr(RTA_DST, "1.0.0.0", &hp);
   getaddr(RTA_GATEWAY, int_ntoa(IP), &hp);
   getaddr(RTA_NETMASK, "255.0.0.0", 0);

   flags |= RTF_UP;
   flags |= RTF_GATEWAY;

   rtmsg_route('a', flags);

   forcenet = 0;

   close(s);
   atexit(Inet_UnsetRoute);
}

#endif

/* EOF */
