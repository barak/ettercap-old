/*
    ettercap -- inet utilities -- Module for LINUX 2.0.x  FULL
                                                   2.2.x  FULL
                                                   2.4.x  FULL

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

    $Id: ec_inet_linux.c,v 1.7 2002/02/11 00:57:25 alor Exp $
*/

#include <ctype.h>

// This file is included from ../ec_inet.c

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
      Error_msg("ec_inet_linux:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   buf_size = 8192;

   for (;;) {
      buf = malloc (buf_size);
      if (buf == NULL)
         Error_msg("ec_inet_linux:%d malloc() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

      ifc.ifc_len = buf_size;
      ifc.ifc_buf = buf;
      memset (buf, 0, buf_size);
      if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0 && errno != EINVAL)
         Error_msg("ec_inet_linux:%d ioctl(SIOCGIFCONF) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

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

         Error_msg("ec_inet_linux:%d ioctl(SIOCGIFFLAGS) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
      }

#ifdef DEBUG
   Debug_msg("Inet_FindIFace -- check for [%s]", ifr.ifr_name);
#endif

      /* Must be up and not the loopback */
      if ((ifr.ifr_flags & IFF_UP) == 0 || (ifr.ifr_flags & IFF_LOOPBACK) != 0)
         continue;

      if ( ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 )
         Error_msg("ec_inet_linux:%d ioctl(SIOCGIFHWADDR) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

      /* Must be ethernet */
      if ( ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER )
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
   Debug_msg("Inet_FindIFace\t\tIface: %s", iface);
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
      Error_msg("ec_inet_linux:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

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

   if ( ioctl(sock, SIOCGIFHWADDR, &ifr) < 0 )
      Error_msg("ec_inet_linux:%d ioctl(SIOCGIFHWADDR) | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

   switch (ifr.ifr_hwaddr.sa_family)
   {
        case ARPHRD_ETHER:    // only ethernet is supported
            break;

        default:
            Error_msg("Device type not supported (only ethernet)");
   }

   close(sock);

   return 0;

}


int Inet_GetIfaceInfo(char *iface, int *MTU, char *MyMAC, unsigned long *IP, unsigned long *NetMask)
{
   int sock;
   struct ifreq ifr;

   sock = Inet_OpenRawSock(iface);

   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

   if (MTU != NULL)
   {
      if ( ioctl(sock, SIOCGIFMTU, &ifr) < 0)
      {
         #ifdef DEBUG
            Debug_msg("Inet_IPBased_Run -- MTU FAILED... assuming 1500");
         #endif
         *MTU = 1500;
      }
      else
         *MTU = ifr.ifr_mtu;
   }


   if (MyMAC != NULL)
   {
      if ( ioctl(sock, SIOCGIFHWADDR, &ifr) < 0 )
         Error_msg("ec_inet_linux:%d ioctl(SIOCGIFHWADDR) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
      memcpy(MyMAC, ifr.ifr_hwaddr.sa_data, 6);
   }

   if (IP != NULL)
   {
      if ( ioctl(sock, SIOCGIFADDR, &ifr) < 0 )
         Error_msg("ec_inet_linux:%d ioctl(SIOCGIFADDR) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
      memcpy((char *)IP, ifr.ifr_addr.sa_data+2, 4);
   }

   if (NetMask != NULL)
   {
      if ( ioctl(sock, SIOCGIFNETMASK, &ifr) < 0 )
         Error_msg("ec_inet_linux:%d ioctl(SIOCGIFNETMASK) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
      memcpy((char *)NetMask, ifr.ifr_addr.sa_data+2, 4);
      if (strcmp(Options.netmask, ""))       // specified on command line
         *NetMask = inet_addr(Options.netmask);
   }

   Inet_CloseRawSock(sock);

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
   int sock;
#ifdef HAVE_PF_PACKET
   struct ifreq ifr;
   struct sockaddr_ll sll;
#else
   struct sockaddr sa;
#endif

#ifdef HAVE_PF_PACKET
   sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#else
   sock = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
#endif
   if (sock < 0)
      Error_msg("ec_inet_linux:%d socket() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

#ifdef DEBUG
   Debug_msg("Inet_OpenRawSock %s \t fd = %d", iface, sock);
#endif

#ifdef HAVE_PF_PACKET

   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

   if ( ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
      Error_msg("ec_inet_linux:%d ioctl(SIOCGIFINDEX) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   memset(&sll, 0, sizeof(sll));
   sll.sll_family = AF_PACKET;
   sll.sll_ifindex = ifr.ifr_ifindex;
   sll.sll_protocol = htons(ETH_P_ALL);

   if ( bind(sock, (struct sockaddr *) &sll, sizeof(sll)) == -1)
      Error_msg("ec_inet_linux:%d bind() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));
#else

   memset(&sa, 0, sizeof(sa));
   strncpy(sa.sa_data, iface, sizeof(sa.sa_data));
   if ( bind(sock, &sa, sizeof(sa)) == -1)
      Error_msg("ec_inet_linux:%d bind() | ERRNO : %d | %s", __LINE__, errno, strerror(errno));

#endif

   return sock;
}



int Inet_GetRawPacket(int sock, char *buffer, int MTU, short *type)
{
   int len = 0;
   socklen_t fromlen;
//#ifdef HAVE_PF_PACKET
//   struct sockaddr_ll from;
//#else
   struct sockaddr from;
   static char MyMAC[6]={0x65,0x74,0x74,0x65,0x72,0x63};
//#endif

   fromlen = sizeof(from);
   len = recvfrom(sock, buffer, MTU+64, MSG_TRUNC, (struct sockaddr *)&from, &fromlen);

   if (len > MTU + ETH_HEADER) len = MTU + ETH_HEADER;   // workaround for bugged kernel (2.2.14)
                                                         // this kernel passes us the MTU + ETH_HEADER + FCS
                                                         // for a total of 1518 byte !!!

//#ifdef HAVE_PF_PACKET
//   if (type != NULL) *type = from.sll_pkttype;
//#else
   // the address returned for SOCK_PACKET lacks the packet type information.
   if (type != NULL)
   {
       if (!strncmp(MyMAC,"etterc",6))    // only the first time...
           Inet_GetIfaceInfo(Options.netiface, NULL, MyMAC, NULL, NULL);
       if (!memcmp(MyMAC,buffer,6))
           *type = 0; // PACKET_HOST
       else
           *type = 1; // !PACKET_HOST
   }
//#endif

   // TODO
   // handle fragmented packets...

   return len;
}



int Inet_SendRawPacket(int sock, char *buffer, int len)
{
   int sent;
   static char first_time = 1;
#ifdef HAVE_PF_PACKET
   static struct sockaddr_ll dest;
   static struct ifreq ifr;
#else
   static struct sockaddr dest;
#endif

   if (first_time)
   {
      memset(&dest, 0, sizeof (dest));
      first_time = 0;

      #ifdef HAVE_PF_PACKET

         memset(&ifr, 0, sizeof(ifr));
         strncpy(ifr.ifr_name, Options.netiface, sizeof(ifr.ifr_name));

         if ( ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
            Error_msg("ec_inet_linux:%d ioctl(SIOCGIFINDEX) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

         dest.sll_family = AF_PACKET;
         dest.sll_ifindex = ifr.ifr_ifindex;
         dest.sll_protocol = htons(ETH_P_ALL);
      #else
         strncpy(dest.sa_data, Options.netiface, sizeof (dest.sa_data));
      #endif
   }

   sent = sendto(sock, buffer, len, 0, (struct sockaddr *)&dest, sizeof(dest));
   if (sent < len)
   {
      while (errno == ENOBUFS)
      {
         usleep(5000);
         sent = sendto(sock, buffer, len, 0, (struct sockaddr *)&dest, sizeof(dest));
         if (sent == len) return (sent);
      }

      Error_msg("ec_inet_linux:%d sendto() %d(%d) | ERRNO : %d | %s \n", __LINE__, len, sent, errno, strerror(errno));
   }

   return (sent);

}



int Inet_SetPromisc(char *iface)
{

   int sock;
   struct ifreq ifr;

#ifdef DEBUG
   Debug_msg("Inet_SetPromisc\tiface: %s", iface);
#endif

   sock = Inet_OpenRawSock(iface);

   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

   if ( ioctl(sock, SIOCGIFFLAGS, &ifr) < 0 )
      Error_msg("ec_inet_linux:%d ioctl(SIOCGIFFLAGS) | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   memset(&old_ifr, 0, sizeof(old_ifr));
   old_ifr.ifr_flags = ifr.ifr_flags;              //save old flags

   if (!(ifr.ifr_flags & IFF_PROMISC))
   {
      ifr.ifr_flags |= IFF_PROMISC;
      if ( ioctl(sock, SIOCSIFFLAGS, &ifr) < 0 )      // promisc mode
         Error_msg("ec_inet_linux:%d ioctl(SIOCSIFFLAGS) | promisc on | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));
      atexit(Inet_Restore_ifr);
   }


   Inet_CloseRawSock(sock);
   return 0;

}



void Inet_Restore_ifr(void)
{
   int sock;
   struct ifreq ifr;

#ifdef DEBUG
   Debug_msg("Inet_Restore_ifr");
#endif

   sock = Inet_OpenRawSock(Options.netiface);

   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, Options.netiface, sizeof(ifr.ifr_name));

   ifr.ifr_flags = old_ifr.ifr_flags;

   if ( ioctl(sock, SIOCSIFFLAGS, &ifr) < 0 )     // flag restoring
      Error_msg("ec_inet_linux:%d ioctl(SIOCSIFFLAGS) | flag restoring | ERRNO : %d | %s \n", __LINE__, errno, strerror(errno));

   Inet_CloseRawSock(sock);
}


void Inet_DisableForwarding(void)
{
   FILE *fd;

   fd = fopen("/proc/sys/net/ipv4/ip_forward", "r");
   if (fd < 0 )
   {
      #ifdef DEBUG
         Debug_msg("ec_inet_linux:%d fopen(/proc/sys/net/ipv4/ip_forward) | ERRNO : %d | %s \n", __LINE__, errno, sys_errlist[errno]);
      #endif
      return;
   }

   fscanf(fd, "%c", &IpForward_status);
   fclose(fd);

#ifdef DEBUG
   Debug_msg("Inet_DisableForwarding from %c", IpForward_status);
#endif

   atexit(Inet_RestoreForwarding);

   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");
   if (fd < 0 )
   {
      #ifdef DEBUG
         Debug_msg("ec_inet_linux:%d fopen(/proc/sys/net/ipv4/ip_forward) | ERRNO : %d | %s \n", __LINE__, errno, sys_errlist[errno]);
      #endif
      return;
   }

   fprintf(fd, "0");
   fclose(fd);
}



void Inet_RestoreForwarding(void)
{
   FILE *fd;

   if (strcmp(ECThread_getname(pthread_self()), PROGRAM)) return;

   fd = fopen("/proc/sys/net/ipv4/ip_forward", "w");
   if (fd < 0 )
   {
      #ifdef DEBUG
         Debug_msg("ec_inet_linux:%d fopen(/proc/sys/net/ipv4/ip_forward) | ERRNO : %d | %s \n", __LINE__, errno, sys_errlist[errno]);
      #endif
      return;
   }

#ifdef DEBUG
   Debug_msg("Inet_RestoreForwarding to %c", IpForward_status);
#endif

   fprintf(fd, "%c", IpForward_status );
   fclose(fd);
}



char *Inet_MacFromIP(unsigned long ip)
{
   int sock_raw;
   static struct arpreq ar;
   struct sockaddr_in *sa_in;

#ifdef DEBUG
   Debug_msg("Inet_MacFromIP");
#endif

   memset((char *)&ar, 0, sizeof(ar));
   strncpy(ar.arp_dev, Options.netiface, sizeof(ar.arp_dev));
   sa_in = (struct sockaddr_in *)&ar.arp_pa;
   sa_in->sin_family = AF_INET;
   sa_in->sin_addr.s_addr = ip;

   sock_raw =Inet_OpenRawSock(Options.netiface);

   if (ioctl(sock_raw, SIOCGARP, (caddr_t)&ar) == -1)  // not in cache... try to find it...
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
         memcpy(&ar.arp_ha.sa_data, MyMAC, ETHER_ADDR_LEN);
         Inet_CloseRawSock(sock);
         Inet_CloseRawSock(sock_raw);
         return (char *) ar.arp_ha.sa_data;
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
               memcpy(&ar.arp_ha.sa_data, &arppkt->source_add, ETHER_ADDR_LEN);
               Inet_Forge_packet_destroy( buf );
               Inet_CloseRawSock(sock);
               Inet_CloseRawSock(sock_raw);
               return (char *) ar.arp_ha.sa_data;
            }
         }
      } while ( TIME_ELAPSED < 0.5 );

      Inet_CloseRawSock(sock);
      Inet_CloseRawSock(sock_raw);
      return ETH_BROADCAST;  // workaround for non local ip
   }

   Inet_CloseRawSock(sock_raw);
   return (char *) ar.arp_ha.sa_data;

}

#ifdef PERMIT_HTTPS

// ARP ENTRY MANAGEMENT ---------------------------

unsigned long SavedIP;
unsigned char SavedMAC[6];

void Inet_UnSetARPEntry(void)
{
    struct arpreq req;
    int sockfd;
    struct sockaddr_in *sa_in;

#ifdef DEBUG
   Debug_msg("Inet_UnSetARPEntry");
#endif

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset((char *) &req, 0, sizeof(req));
    sa_in = (struct sockaddr_in *)&req.arp_pa;
    sa_in->sin_family = AF_INET;
    sa_in->sin_addr.s_addr = SavedIP;
    req.arp_flags = ATF_PERM | ATF_COM;

    memcpy(req.arp_ha.sa_data, SavedMAC, 6);
    strlcpy(req.arp_dev, Options.netiface, sizeof(req.arp_dev));

    ioctl(sockfd, SIOCDARP, &req);

    close(sockfd);
}


int Inet_SetARPEntry(unsigned long IP, char MAC[6])
{
    struct arpreq req;
    int sockfd;
    struct sockaddr_in *sa_in;
    int retval;

#ifdef DEBUG
   Debug_msg("Inet_SetARPEntry");
#endif

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset((char *) &req, 0, sizeof(req));
    sa_in = (struct sockaddr_in *)&req.arp_pa;
    sa_in->sin_family = AF_INET;
    sa_in->sin_addr.s_addr = IP;
    req.arp_flags = ATF_PERM | ATF_COM;

    memcpy(req.arp_ha.sa_data, MAC, 6);
    strlcpy(req.arp_dev, Options.netiface, sizeof(req.arp_dev));

    retval = ioctl(sockfd, SIOCSARP, &req);

    close(sockfd);

    SavedIP=IP;
    memcpy(SavedMAC, MAC, 6);
    atexit(Inet_UnSetARPEntry);

    return retval;
}

// ROUTE MANAGEMENT ---------------------------

struct rtentry
{
    unsigned long int rt_pad1;
    struct sockaddr_in rt_dst;
    struct sockaddr_in rt_gateway;
    struct sockaddr_in rt_genmask;
    unsigned short int rt_flags;
    short int rt_pad2;
    unsigned long int rt_pad3;
    unsigned char rt_tos;
    unsigned char rt_class;
    short int rt_pad4;
    short int rt_metric;
    char *rt_dev;
    unsigned long int rt_mtu;
    unsigned long int rt_window;
    unsigned short int rt_irtt;
};

void Inet_UnsetRoute(void)
{
    int skfd;
    struct rtentry rt;

#ifdef DEBUG
   Debug_msg("Inet_UnsetRoute");
#endif

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset((char *)&rt,0, sizeof(struct rtentry));

    rt.rt_dst.sin_family=AF_INET;
    rt.rt_dst.sin_addr.s_addr=inet_addr("1.0.0.1");
    rt.rt_genmask.sin_family=AF_INET;
    rt.rt_genmask.sin_addr.s_addr=inet_addr("255.255.255.255");
    rt.rt_flags=5;
    rt.rt_dev=Options.netiface;

    ioctl(skfd, SIOCDELRT, &rt);

    rt.rt_dst.sin_addr.s_addr=inet_addr("1.0.0.0");
    rt.rt_gateway.sin_family=AF_INET;
    rt.rt_gateway.sin_addr.s_addr=inet_addr("1.0.0.1");
    rt.rt_genmask.sin_addr.s_addr=inet_addr("255.0.0.0");
    rt.rt_flags=3;

    ioctl(skfd, SIOCDELRT, &rt);

    close(skfd);
}

void Inet_SetRoute(void)
{
    int skfd;
    struct rtentry rt;

#ifdef DEBUG
   Debug_msg("Inet_SetRoute");
#endif

    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset((char *)&rt,0, sizeof(struct rtentry));

    rt.rt_dst.sin_family=AF_INET;
    rt.rt_dst.sin_addr.s_addr=inet_addr("1.0.0.1");
    rt.rt_genmask.sin_family=AF_INET;
    rt.rt_genmask.sin_addr.s_addr=inet_addr("255.255.255.255");
    rt.rt_flags=5;
    rt.rt_dev=Options.netiface;

    ioctl(skfd, SIOCADDRT, &rt);

    rt.rt_dst.sin_addr.s_addr=inet_addr("1.0.0.0");
    rt.rt_gateway.sin_family=AF_INET;
    rt.rt_gateway.sin_addr.s_addr=inet_addr("1.0.0.1");
    rt.rt_genmask.sin_addr.s_addr=inet_addr("255.0.0.0");
    rt.rt_flags=3;

    ioctl(skfd, SIOCADDRT, &rt);

    close(skfd);

    atexit(Inet_UnsetRoute);
}

#endif

/* EOF */
