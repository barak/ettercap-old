%define prefix /usr

Summary:    ettercap is a ncurses-based sniffer/interceptor utility
Name:       ettercap
Version:    0.6.4
Release:    1
Serial:     20020222
Packager:   ALoR <alor@users.sourceforge.net>
Source:     http://ettercap.sourceforge.net/download/%{name}-%{version}.tar.gz
URL:        http://ettercap.sourceforge.net/
License:    GPL
Group:      Networking/Utilities
Prefix:     %{prefix}
Buildroot:  %{_tmppath}/%{name}-%{version}-root

%description
ettercap is a network sniffer/interceptor/logger for ethernet LANs (both switched or not).
It supports active and passive dissection of many protocols (even ciphered ones, like
SSH and HTTPS). Data injection in an established connection and filtering (substitute
or drop a packet) on the fly is also possible, keeping the connection sincronized. Many
sniffing modes were implemented to give you a powerful and complete sniffing suite.
Plugins are supported. It has the ability to check whether you are in a switched LAN or
not, and to use OS fingerprints (active or passive) to let you know the geometry of the LAN.
The passive scan of the lan retrives infos about: hosts in the lan, open ports, services
version, type of the host (gateway, router or simple host) and extimated distance in hop.

%prep
%setup -q

%build
./configure --prefix=%{prefix} --disable-debug --mandir=%{_mandir}
make
make plug-ins

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
make plug-ins_install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_mandir}/man8/*
%doc COPYING README README.PLUGINS README.WIN32 HISTORY CHANGELOG AUTHORS TODO THANKS KNOWN-BUGS PORTINGS INSTALL ./plugins/H01_zaratan/ZARATAN.HOWTO
%{prefix}/sbin/*
%{prefix}/share/ettercap/*
%{prefix}/lib/ettercap/*
