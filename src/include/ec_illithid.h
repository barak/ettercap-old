
#if !defined(EC_ILLITHID_H)
#define EC_ILLITHID_H


extern pthread_t Illithid_ARPBased_GetConnections(char *iface, char *IP1p, char *IP2p, char *MAC1, char *MAC2);
extern pthread_t Illithid_PublicARP_GetConnections(char *iface, char *IP1p, char *IP2p, char *MAC1, char *MAC2);
extern pthread_t Illithid_IPBased_GetConnections(char *iface, char *IP1p, char *IP2p);
extern pthread_t Illithid_MACBased_GetConnections(char *iface, char *MAC1p, char *MAC2p);

#endif

/* EOF */
