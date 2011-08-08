
#if !defined(EC_ERROR_H)
#define EC_ERROR_H


#include <errno.h>

extern void Error_msg(char *message, ...);
extern void Error_critical_msg(char *file, char *function, int line, char *message);

#define ERROR_MSG(x) Error_critical_msg(__FILE__, __FUNCTION__, __LINE__, x)

#endif

/* EOF */
