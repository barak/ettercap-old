
#if !defined(EC_BUFFER_H)
#define EC_BUFFER_H

extern int Buffer_Get(int bufferID, void *data, short size);   // use it like read()
extern int Buffer_Put(int bufferID, void *data, short size);   // use it like write()
extern int Buffer_Create(int len);                             // creates the shared buffer
extern void Buffer_Flush(int ID);                              // flush it

#endif

/* EOF */



