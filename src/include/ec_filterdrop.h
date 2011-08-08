
#if !defined(EC_FILTERDROP_H)
#define EC_FILTERDROP_H


extern int FilterDrop_MakefilterTCP(u_char *buf_ip, int *buflen, short maxlen, DROP_FILTER *filters, char *mod);
extern int FilterDrop_MakefilterUDP(u_char *buf_ip, int *buflen, short maxlen, DROP_FILTER *filters, char *mod);

extern int FilterDrop_strescape( char *dst, char *src);
extern int FilterDrop_ParseWildcard(char *dst, char *src, size_t size);

extern void FilterDrop_AddFilter(DROP_FILTER *ptr);
extern void FilterDrop_DelFilter(DROP_FILTER *ptr, int i);
extern void FilterDrop_SaveFilter(void);
extern int FilterDrop_CheckMode(DROP_FILTER *ptr, short mode);
extern int FilterDrop_Validation(DROP_FILTER *ptr);

extern pthread_mutex_t filter_mutex;

#endif

/* EOF */
