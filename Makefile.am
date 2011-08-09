include $(top_srcdir)/Makefile.am.common

SUBDIRS = man share include include src utils

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

icondir = $(datadir)/icons/hicolor/32x32/apps/
dist_icon_DATA = ettercap.xpm

desktopdir = $(datadir)/applications
dist_desktop_DATA = ettercap.desktop

CLEANFILES = -R auto4te.cache *~ *.log *.out *.cache *.so ettercap etterlog etterfilter

dist-hook:
	cat $(distdir)/Makefile.am.common | sed s/#no/no/g > $(distdir)/Makefile.am.common

test: all
	rm -f ettercap etterfilter etterlog *.so
	ln -fs ./src/ettercap ./
	ln -fs ./utils/etterlog/etterlog ./
	ln -fs ./utils/etterfilter/etterfilter ./
	find ./plug-ins -name '*.so' -exec ln -fs {} ./ \;
	./shtool fixperm ./

# vim:ts=4:noexpandtab

