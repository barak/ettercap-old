include $(top_srcdir)/Makefile.am.common

ACLOCAL_AMFLAGS = -I libltdl/m4

SUBDIRS = man share include include src utils desktop

if PLUGINS
   SUBDIRS += plug-ins
endif


EXTRA_DIST = AUTHORS \
             CHANGELOG \
             LICENSE \
             README \
             README.BINARIES \
             README.BUGS \
             README.GIT \
             README.PLATFORMS \
             THANKS \
             TODO \
             TODO.TESTING \
             Makefile.am.common \
             Makefile.mingw.in \
             shtool \
             contrib/* \
             doc/*

CLEANFILES = -R auto4te.cache *~ *.log *.out *.cache *.so ettercap etterlog etterfilter

test: all
	rm -f ettercap etterfilter etterlog *.so
	ln -fs ./src/ettercap ./
	ln -fs ./utils/etterlog/etterlog ./
	ln -fs ./utils/etterfilter/etterfilter ./
	find ./plug-ins -name '*.so' -exec ln -fs {} ./ \;
	./shtool fixperm ./

# vim:ts=4:noexpandtab

