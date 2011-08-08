
#if !defined(EC_DISSECTOR_H)
#define EC_DISSECTOR_H


// structures....

typedef struct {
   char mode;
   short proto;
   u_short port;
   int (*dissector)(u_char *, CONNECTION *, SNIFFED_DATA *, int, short);
   char active;
   char name[15];
} DISSECTOR;

typedef struct {
   short port;
   struct RPC_PORTS *next;
} RPC_PORTS;

typedef struct {
   int program;
   int version;
   short proto;
   int (*dissector)(u_char *, CONNECTION *, SNIFFED_DATA *, int, short);
   RPC_PORTS *ports;
} RPC_DISSECTOR;

// functions...
extern int Dissector_Connections( char mode, short proto, u_char *data, CONNECTION *data_to_ettercap, SNIFFED_DATA *sniff_data_to_ettercap, int Conn_Mode );
extern void Dissector_SetHandle( char *name, char active, short port, short proto);
extern int Dissector_StateMachine_GetStatus(CONNECTION *data_to_ettercap, char *info);
extern int Dissector_StateMachine_SetStatus(CONNECTION *data_to_ettercap, char status, char *info);
extern int Dissector_base64decode(char *bufplain, const char *bufcoded);

// macros....
#define FUNC_DISSECTOR(func) int func( u_char *data, CONNECTION *data_to_ettercap, SNIFFED_DATA *sniff_data_to_ettercap, int Conn_Mode, short SERV_PORT )

/*
#define ONLY_CONNECTION    CONNECTION *data_to_ettercap; \
                           if (!Conn_Mode) return 0; \
                           data_to_ettercap = (CONNECTION *)vdata_to_ettercap

#define DATA_DISSECTOR     CONNECTION *data_to_ettercap; \
                           SNIFFED_DATA *sniff_data_to_ettercap; \
                           data_to_ettercap = (CONNECTION *)vdata_to_ettercap; \
                           sniff_data_to_ettercap = (SNIFFED_DATA *)vdata_to_ettercap

*/
#define ONLY_CONNECTION {}
#define DATA_DISSECTOR  {}

// dissectors....
extern FUNC_DISSECTOR(Dissector_ftp);        // 21
#ifdef HAVE_OPENSSL
extern FUNC_DISSECTOR(Dissector_ssh);        // 22
#endif
extern FUNC_DISSECTOR(Dissector_telnet);     // 23
extern FUNC_DISSECTOR(Dissector_http);       // 80 8080
extern FUNC_DISSECTOR(Dissector_pop);        // 110
extern FUNC_DISSECTOR(Dissector_portmapTCP); // 111
extern FUNC_DISSECTOR(Dissector_portmapUDP); // 111   UDP
extern FUNC_DISSECTOR(Dissector_nntp);       // 119
extern FUNC_DISSECTOR(Dissector_smb);        // 139
extern FUNC_DISSECTOR(Dissector_imap);       // 143 220
extern FUNC_DISSECTOR(Dissector_snmp);       // 161              UDP
extern FUNC_DISSECTOR(Dissector_bgp);        // 179
extern FUNC_DISSECTOR(Dissector_ldap);       // 389
#if defined (HAVE_OPENSSL) && defined (PERMIT_HTTPS)
extern FUNC_DISSECTOR(Dissector_https);      // 443
#endif
extern FUNC_DISSECTOR(Dissector_rlogin);     // 512 513 514
extern FUNC_DISSECTOR(Dissector_rip);        // 520              UDP
extern FUNC_DISSECTOR(Dissector_socks);      // 1080
extern FUNC_DISSECTOR(Dissector_mysql);      // 3306
extern FUNC_DISSECTOR(Dissector_icq);        // 4000 5190 ALL_P  UDP
extern FUNC_DISSECTOR(Dissector_vnc);        // 5900-5905
extern FUNC_DISSECTOR(Dissector_x11);        // 6000-6005
extern FUNC_DISSECTOR(Dissector_napster);    // 6666 7777 8888
extern FUNC_DISSECTOR(Dissector_irc);        // 6667-6669
extern FUNC_DISSECTOR(Dissector_hl_rcon);    // 27015            UDP
extern FUNC_DISSECTOR(Dissector_pcanywhere); // 65301

// RPC Dissectors
extern FUNC_DISSECTOR(Dissector_mountdTCP);
extern FUNC_DISSECTOR(Dissector_mountdUDP);

#endif

/* EOF */
