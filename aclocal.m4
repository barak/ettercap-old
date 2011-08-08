
dnl
dnl EC_MESSAGE(MESSAGE)
dnl

AC_DEFUN(EC_MESSAGE,[
   AC_MSG_RESULT()
   AC_MSG_RESULT(${SB}$1...${EB})
   AC_MSG_RESULT()
])

dnl
dnl EC_CHECK_OPTION(STRING, VAR)
dnl

AC_DEFUN(EC_CHECK_OPTION,[
   echo "$1 ${SB}$2${EB}"
])


dnl
dnl EC_LINUX_KERNEL()
dnl

AC_DEFUN(EC_LINUX_KERNEL,[

   AC_MSG_CHECKING(Linux kernel version)
   major=`uname -r  | cut -f1 -d"."`
   minor=`uname -r  | cut -f2 -d"."`
   uname=`uname -r`
   AC_MSG_RESULT($uname)
   if test "$major$minor" -lt 20; then
      AC_MSG_WARN(*******************************);
      AC_MSG_WARN(* Kernel >= 2.0.x REQUIRED !! *);
      AC_MSG_WARN(*******************************);
      exit;
   fi
])


dnl
dnl EC_FREEBSD_VERSION()
dnl

AC_DEFUN(EC_FREEBSD_VERSION,[

   AC_MSG_CHECKING(FreeBSD version)
   major=`uname -r  | cut -f1 -d"."`
   minor=`uname -r  | cut -f2 -d"." | cut -f1 -d"-"`
   uname=`uname -r`
   AC_MSG_RESULT($uname)
   if test "$major$minor" -lt 40; then
      AC_MSG_WARN(************************************************);
      AC_MSG_WARN(* Tested only on FreeBSD 4.x !!                *);
      AC_MSG_WARN(* Please send me comment patches or bug-report *);
      AC_MSG_WARN(* on how ettercap works within your system...  *);
      AC_MSG_WARN(************************************************);
   fi

])


dnl
dnl EC_DARWIN_KERNEL()
dnl

AC_DEFUN(EC_DARWIN_KERNEL,[

   AC_MSG_CHECKING(Darwin version)
   major=`uname -r  | cut -f1 -d"."`
   minor=`uname -r  | cut -f2 -d"."`
   uname=`uname -r`
   AC_MSG_RESULT($uname)
   if test "$major$minor" -lt 14; then
		ac_cv_ec_undefined="suppress"
	elif test "$major$minor" -gt 13; then
		ac_cv_ec_undefined="error"
   fi
])


dnl
dnl EC_PF_PACKET()
dnl
dnl   returns  HAVE_PF_PACKET
dnl            ac_cv_ec_nopf=1  (if fails)
dnl

AC_DEFUN(EC_PF_PACKET,[

   AC_MSG_CHECKING(if you can create PF_PACKET socket)
   AC_TRY_COMPILE([
   #include <arpa/inet.h>
   #include <sys/socket.h>
   #include <features.h>         /* for the glibc version number */
   #if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
   #include <net/ethernet.h>     /* the L2 protocols */
   #else
   #include <asm/types.h>
   #include <linux/if_ether.h>   /* The L2 protocols */
   #endif],
   [ int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); ],
   [  AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_PF_PACKET,1) ],
   [  AC_MSG_RESULT(no);
      ac_cv_ec_nopf=1 ]
   )

])


dnl
dnl EC_SOCK_PACKET()
dnl
dnl   returns  HAVE_SCOK_PACKET
dnl            ac_cv_ec_nosock=1 (if fails)
dnl

AC_DEFUN(EC_SOCK_PACKET,[

   AC_MSG_CHECKING(if you can create SOCK_PACKET socket)
   AC_TRY_COMPILE([
   #include <arpa/inet.h>
   #include <sys/socket.h>
   #include <features.h>         /* for the glibc version number */
   #if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
   #include <net/ethernet.h>     /* the L2 protocols */
   #else
   #include <asm/types.h>
   #include <linux/if_ether.h>   /* The L2 protocols */
   #endif],
   [ int sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL)); ],
   [  AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_SOCK_PACKET,1) ],
   [  AC_MSG_RESULT(no);
      ac_cv_ec_nosock=1 ]
   )

])



dnl
dnl     EC_SOCKLEN_CHECK
dnl
dnl results:
dnl
dnl     HAVE_SOCKLEN_T
dnl

AC_DEFUN(EC_SOCKLEN_CHECK,
   [AC_MSG_CHECKING(for socklen_t in sys/socket.h)

   AC_TRY_RUN([
      #include <sys/types.h>
      #include <sys/socket.h>

      int main()
      {
         socklen_t from;
         from = sizeof(socklen_t);

         return 0;
      }
   ],
   [  AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_SOCKLEN_T)
      ],
      AC_MSG_RESULT(no);
      ,
      AC_MSG_RESULT(unkown when cross-compiling)
   )

])


dnl
dnl Checks to see if the sockaddr struct has the 4.4 BSD sa_len member
dnl
dnl usage:
dnl
dnl     AC_LBL_SOCKADDR_SA_LEN
dnl
dnl results:
dnl
dnl     HAVE_SOCKADDR_SA_LEN (defined)
dnl
AC_DEFUN(AC_LBL_SOCKADDR_SA_LEN,
    [AC_MSG_CHECKING(if sockaddr struct has sa_len member)
    AC_CACHE_VAL(ac_cv_lbl_sockaddr_has_sa_len,
        AC_TRY_COMPILE([
#       include <sys/types.h>
#       include <sys/socket.h>],
        [u_int i = sizeof(((struct sockaddr *)0)->sa_len)],
        ac_cv_lbl_sockaddr_has_sa_len=yes,
        ac_cv_lbl_sockaddr_has_sa_len=no))
    AC_MSG_RESULT($ac_cv_lbl_sockaddr_has_sa_len)
    if test $ac_cv_lbl_sockaddr_has_sa_len = yes ; then
            AC_DEFINE(HAVE_SOCKADDR_SA_LEN,1,[if struct sockaddr has sa_len])
    fi])



dnl
dnl Checks to see if unaligned memory accesses fail			(from libpcap aclocal.m4)
dnl
dnl usage:
dnl
dnl	AC_LBL_UNALIGNED_ACCESS
dnl
dnl results:
dnl
dnl	LBL_ALIGN (DEFINED)
dnl
AC_DEFUN(AC_LBL_UNALIGNED_ACCESS,
    [AC_MSG_CHECKING(if unaligned accesses fail)
    AC_CACHE_VAL(ac_cv_lbl_unaligned_fail,
	[case "$target_cpu" in

	# XXX: should also check that they don't do weird things (like on arm)
	alpha*|arm*|hp*|mips|sparc)
		ac_cv_lbl_unaligned_fail=yes
		;;

	*)
		cat >conftest.c <<EOF
#		include <sys/types.h>
#		include <sys/wait.h>
#		include <stdio.h>
		unsigned char a[[5]] = { 1, 2, 3, 4, 5 };
		main() {
		unsigned int i;
		pid_t pid;
		int status;
		/* avoid "core dumped" message */
		pid = fork();
		if (pid <  0)
			exit(2);
		if (pid > 0) {
			/* parent */
			pid = waitpid(pid, &status, 0);
			if (pid < 0)
				exit(3);
			exit(!WIFEXITED(status));
		}
		/* child */
		i = *(unsigned int *)&a[[1]];
		printf("%d\n", i);
		exit(0);
		}
EOF
		${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS \
		    conftest.c $LIBS >/dev/null 2>&1
		if test ! -x conftest ; then
			dnl failed to compile for some reason
			ac_cv_lbl_unaligned_fail=yes
		else
			./conftest >conftest.out
			if test ! -s conftest.out ; then
				ac_cv_lbl_unaligned_fail=yes
			else
				ac_cv_lbl_unaligned_fail=no
			fi
		fi
		rm -f conftest* core core.conftest
		;;
	esac])
	AC_MSG_RESULT($ac_cv_lbl_unaligned_fail)
	if test $ac_cv_lbl_unaligned_fail = yes ; then
		AC_DEFINE(LBL_ALIGN,1,[if unaligned access fails])
	fi])



AC_DEFUN(EC_CHECK_DATE,[
	today=`date +%m%d`
	if test "$today" -eq "0930" -o "$today" -eq "1114"; then

		if test "$today" -eq "1114"; then
			who="ALoR"
		elif test "$today" -eq "0930"; then
			who="NaGA"
		fi

		echo
		echo
		echo "********************************"
		echo "*                              *"
		echo "* Today is the $who's birthday *"
		echo "*                              *"
		echo "********************************"
		echo
		echo "  Only for today ettercap is a"
		echo " cardware or emailware software."
		echo
		echo " a mail will be appreciated... ;)"
		echo
		exit
	fi
])



dnl
dnl EC_PTHREAD_CHECK()
dnl            ac_cv_ec_nopthread=1 (if fails)
dnl

AC_DEFUN(EC_PTHREAD_CHECK,[

	AC_SEARCH_LIBS(pthread_create, pthread,,
		[
			AC_MSG_CHECKING(whether $CC accepts -pthread)
			CFLAGS_store="$CFLAGS"
			CFLAGS="$CFLAGS -pthread"
			AC_TRY_COMPILE([#include <pthread.h>],[pthread_create(NULL, NULL, NULL, NULL);],
				[AC_MSG_RESULT(yes)
				 LIBS="$LIBS -pthread"],
				[AC_MSG_RESULT(no)
					CFLAGS="$CFLAGS_store"
					AC_MSG_WARN(***************************);
					AC_MSG_WARN(* PTHREAD ARE REQUIRED !! *);
					AC_MSG_WARN(***************************);
					exit
				])
			unset CFLAGS_store
		]
	)

])