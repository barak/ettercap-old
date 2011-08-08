
#include <pthread.h>

extern char * ECThread_getname(pthread_t id);
extern void ECThread_register(pthread_t id, char * name);
extern pthread_t ECThread_create(char * name, void *(*function)(void *), void *args);
extern void ECThread_destroy(pthread_t id);

/* EOF */
