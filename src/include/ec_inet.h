
#if !defined(EC_INET_H)
#define EC_INET_H


extern char * Inet_HostName(char *ip);
extern char * Inet_NameToIp(char *name);
extern char * Inet_MyIPAddress(void);
extern char * Inet_MyMACAddress(void);
extern char * Inet_MySubnet(void);

extern int Inet_HostInLAN(void);
extern SniffingHost * Inet_NoSniff(void);

extern void Inet_PutMACinString(char *mac_string, unsigned char *MAC);
extern int Inet_GetMACfromString(char *mac_string, unsigned char *MAC);
extern int Inet_CheckSwitch(void);

extern int Inet_Fake_Host(void);

#ifdef CYGWIN
typedef struct sh {
	SOCKET fd;
	struct sockaddr_in sin;
} socket_handle;
#else
typedef int socket_handle;
#endif

extern socket_handle Inet_OpenSocket(char *host, short port);
extern int Inet_CloseSocket(socket_handle sh);
extern int Inet_Http_Send(socket_handle sh, char *payload);
extern int Inet_Http_Receive(socket_handle sh, char *payload, size_t size);

extern int Inet_SendLargeTCPPacket(int sock, char *buffer, int len, int MTU);
extern char * Inet_Save_Host_List(void);

// Following are architecture dependent !! implementations are in ./src/`uname`/ec_inet_`uname`.c

extern int Inet_FindIFace(char *iface);
extern int Inet_CorrectIface(char *iface);

extern int Inet_GetIfaceInfo(char *iface, int *MTU, char *MyMAC, unsigned long *IP, unsigned long *NetMask);
extern int Inet_SetPromisc(char *iface);

extern int Inet_OpenRawSock(char *iface);
extern void Inet_CloseRawSock(int sock);
extern int Inet_GetRawPacket(int sock, char *buffer, int MTU, short *type);
extern int Inet_SendRawPacket(int sock, char *buffer, int len);
extern int Inet_SetARPEntry(unsigned long IP, char MAC[6]);
extern void Inet_DisableForwarding(void);
extern void Inet_SetRoute(void);
extern char *Inet_MacFromIP(unsigned long ip);

#endif

/* EOF */
