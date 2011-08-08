
#if !defined(EC_DECODEDATA_H)
#define EC_DECODEDATA_H

extern void Decodedata_SetArrayIndex(CONNECTION *data, int index);
extern int Decodedata_MakeConnectionList(CONNECTION *data);
extern int Decodedata_RefreshConnectionList(void);

extern int Decodedata_GetPassiveOS(char *fingerprint, char *os);
extern int Decodedata_MakePassiveList(PASSIVE_DATA *data);
extern int Decodedata_FreePassiveList(void);

extern char * Decodedata_GetType(char proto, int port1, int port2);
extern char * Decodedata_GetAsciiData(char *buffer, int buff_len);
extern char * Decodedata_GetTextData(char *buffer, int buff_len);
extern char * Decodedata_GetHexData(char *buffer, int buff_len, short dimX);
extern char * Decodedata_TCPFlags(char flags);

extern void Decodedata_ConvertPassiveToHost(void);
extern void Decodedata_Passive_SortList(void);

#endif

/* EOF */
