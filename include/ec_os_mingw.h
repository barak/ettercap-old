#ifndef EC_OS_MINGW_H
#define EC_OS_MINGW_H

#include <malloc.h>     /* for alloca() */
#include <winsock2.h>   /* u_char etc. */

#if !defined(HAVE_SLEEP)
   #define sleep(sec)    Sleep (1000*(sec))
#endif

#if !defined(HAVE_USLEEP)
   #define usleep(usec)  Sleep ((usec)/1000)
#endif

#if !defined(HAVE_GETUID)
   #define getuid()      (0)
#endif

#if !defined(HAVE_GETGID)
   #define getgid()   	 (0)
#endif

#if !defined(HAVE_GETEUID)
   #define geteuid()     (0)
#endif

#if !defined(HAVE_GETEUID)
   #define getegid()     (0)
#endif

#if !defined(HAVE_SETUID)
   #define setuid(x)     (0)
#endif

#if !defined(HAVE_SETGID)
   #define setgid(x)     (0)
#endif

#if !defined(HAVE_RANDOM)
   #define random()      rand()
#endif

#if !defined(HAVE_SRANDOM)
   #define srandom(s)    srand(s)
#endif

#if !defined(_TIMEVAL_DEFINED)
   #define _TIMEVAL_DEFINED
   struct timeval {
          long    tv_sec;
          long    tv_usec;
        };
#endif

#if !defined(HAVE_STRUCT_TIMEZONE)
   #define HAVE_STRUCT_TIMEZONE
   struct timezone {
          int tz_minuteswest;     /* minutes west of Greenwich */
          int tz_dsttime;         /* type of dst correction */
        };
#endif

#undef  _U_
#if defined(__GNUC__)
   #define _U_  __attribute__((unused))
#else
   #define _U_
#endif

#ifndef EINPROGRESS
#define EINPROGRESS  WSAEINPROGRESS
#endif

#ifndef EALREADY
#define EALREADY     WSAEALREADY
#endif

#ifndef EISCONN
#define EISCONN WSAEISCONN
#endif

#define gettimeofday(tv,tz)    ec_win_gettimeofday (tv, tz)
#define strsignal(signo)       ec_win_strsignal (signo)
#define poll(p,n,t)            ec_win_poll (p,n,t)
#define dn_expand(m,e,c,ex,l)  ec_win_dn_expand (m, e, c, ex, l)
#define dn_comp(e,c,l,d,ld)    ec_win_dn_comp(e,c,l,d,ld)

extern int         ec_win_dn_expand (const u_char *msg, const u_char *eom_orig,
                                     const u_char *comp_dn, char *exp_dn, int length);
extern int         ec_win_dn_comp   (const char *exp_dn, u_char *comp_dn, int length,
                                     u_char **dnptrs, u_char **lastdnptr);

extern int         ec_win_gettimeofday (struct timeval *tv, struct timezone *tz);
extern const char *ec_win_strsignal (int signo);

/* poll() emulation
 */
#define POLLIN   0x0001
#define POLLPRI  0x0002   /* not used */
#define POLLOUT  0x0004
#define POLLERR  0x0008
#define POLLHUP  0x0010   /* not used */
#define POLLNVAL 0x0020   /* not used */

struct pollfd {
       int fd;
       int events;     /* in param: what to poll for */
       int revents;    /* out param: what events occured */
     };

#undef  HAVE_POLL
#define HAVE_POLL 1

extern int ec_win_poll (struct pollfd *p, int num, int timeout);

/*  User/program dir
 */
extern const char *ec_win_get_user_dir (void);
extern const char *ec_win_get_ec_dir (void);

/* This is a stupid hack. How can we on compile time know the install location on a
 * on-Unix system?
 */
#ifndef INSTALL_PREFIX
#define INSTALL_PREFIX  ec_win_get_ec_dir()
#endif

/* Unix mmap() emulation
 */
#ifndef HAVE_MMAP
   #define PROT_READ    0x1            /* page can be read */
   #define PROT_WRITE   0x2            /* page can be written */
   #define PROT_EXEC    0x4            /* page can be executed (not supported) */
   #define PROT_NONE    0x0            /* page can not be accessed (not supported) */
   #define MAP_SHARED   0x01           /* share changes (ot supported) */
   #define MAP_PRIVATE  0x02           /* make mapping private (not supportd) */
   #define MAP_FAILED   NULL

   #define mmap(xx1,size,prot,xx2,fd,xx3)  ec_win_mmap (fd,size,prot)
   #define munmap(handle,size)             ec_win_munmap ((const void*)(handle), size)

   extern void *ec_win_mmap (int fd, size_t size, int prot);
   extern int   ec_win_munmap (const void *handle, size_t size);
#endif

/* dlopen() emulation (not exported)
 */
#if !defined(HAVE_DLOPEN)
  #define RTLD_NOW 0

  #define dlopen(dll,flg)      ec_win_dlopen (dll, flg)
  #define lt_dlopen(dll)       ec_win_dlopen (dll, 0)
  #define lt_dlopenext(dll)    ec_win_dlopen (dll, 0)
  #define dlsym(hnd,func)      ec_win_dlsym (hnd, func)
  #define lt_dlsym(hnd,func)   ec_win_dlsym (hnd, func)
  #define dlclose(hnd)         ec_win_dlclose (hnd)
  #define lt_dlclose(hnd)      ec_win_dlclose (hnd)
  #define dlerror()            ec_win_dlerror()
  #define lt_dlerror()         ec_win_dlerror()
  #define lt_dlinit()          (0)
  #define lt_dlexit()          (0)

  extern void       *ec_win_dlopen  (const char *dll_name, int flags _U_);
  extern void       *ec_win_dlsym   (const void *dll_handle, const char *func_name);
  extern void        ec_win_dlclose (const void *dll_handle);
  extern const char *ec_win_dlerror (void);
#endif

/*
 * fork() emulation
 */
#if !defined(HAVE_FORK)
  #define fork()  ec_win_fork()

  extern int ec_win_fork(void);
#endif
  
/* Missing stuff for ec_resolv.h / ec_win_dnexpand()
 */
#ifndef INT16SZ
#define INT16SZ 2
#endif

#ifndef INT32SZ
#define INT32SZ 4
#endif

#undef  GETSHORT
#define GETSHORT(s, cp) do { \
        register u_char *t_cp = (u_char *)(cp); \
        (s) = ((u_short)t_cp[0] << 8) \
            | ((u_short)t_cp[1]); \
        (cp) += INT16SZ; \
      } while (0)

#undef  GETLONG
#define GETLONG(l, cp) do { \
        register u_char *t_cp = (u_char *)(cp); \
        (l) = ((u_long)t_cp[0] << 24) \
            | ((u_long)t_cp[1] << 16) \
            | ((u_long)t_cp[2] << 8) \
            | ((u_long)t_cp[3]); \
        (cp) += INT32SZ; \
      } while (0)

#undef  PUTSHORT
#define PUTSHORT(s, cp) do { \
        register u_short t_s = (u_short)(s); \
        register u_char *t_cp = (u_char *)(cp); \
        *t_cp++ = t_s >> 8; \
        *t_cp   = t_s; \
        (cp) += INT16SZ; \
      } while (0)

#undef  PUTLONG
#define PUTLONG(l, cp) do { \
        register u_long t_l = (u_long)(l); \
        register u_char *t_cp = (u_char *)(cp); \
        *t_cp++ = t_l >> 24; \
        *t_cp++ = t_l >> 16; \
        *t_cp++ = t_l >> 8; \
        *t_cp   = t_l; \
        (cp) += INT32SZ; \
      } while (0)

#endif /* EC_WIN_MISC_H */