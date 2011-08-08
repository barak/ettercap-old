############################################################################
#                                                                          #
#  ettercap -- etter.passive.os.fp -- passive OS fingerprint database      #
#                                                                          #
#  Copyright (C) 2001  ALoR <alor@users.sourceforge.net>                   #
#                      NaGA <crwm@freemail.it>                             #
#                                                                          #
#  This program is free software; you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation; either version 2 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
############################################################################
#                                                                          #
#  Last updated on : $Date: 2002/02/11 20:31:56 $                          #
#  Total entries   : 675                                                   #
#                                                                          #
############################################################################
#                                                                          #
# The fingerprint database has the following structure:                    #
#                                                                          #
# WWWW:MSS:TTL:WS:S:N:D:T:F:LEN:OS                                         #
#                                                                          #
# WWWW: 4 digit hex field indicating the TCP Window Size                   #
# MSS : 4 digit hex field indicating the TCP Option Maximum Segment Size   #
#       if omitted in the packet or unknown it is "_MSS"                   #
# TTL : 2 digit hex field indicating the IP Time To Live                   #
# WS  : 2 digit hex field indicating the TCP Option Window Scale           #
#       if omitted in the packet or unknown it is "WS"                     #
# S   : 1 digit field indicating if the TCP Option SACK permitted is true  #
# N   : 1 digit field indicating if the TCP Options contain a NOP          #
# D   : 1 digit field indicating if the IP Don't Fragment flag is set      #
# T   : 1 digit field indicating if the TCP Timestamp is present           #
# F   : 1 digit ascii field indicating the flag of the packet              #
#       S = SYN                                                            #
#       A = SYN + ACK                                                      #
# LEN : 2 digit hex field indicating the length of the packet              #
#       if irrilevant or unknown it is "LT"                                #
# OS  : an ascii string representing the OS                                #
#                                                                          #
# IF YOU FIND A NEW FINGERPRING, PLEASE MAIL IT US WITH THE RESPECTIVE OS  #
# or use the appropriate form at:                                          #
#    http://ettercap.sourceforge.net/index.php?s=stuff&p=fingerprint       #
#                                                                          #
# TO GET THE LATEST DATABASE:                                              #
#                                                                          #
#    http://cvs.sourceforge.net/cgi-bin/viewcvs.cgi/~checkout~/ettercap/   #
#           ettercap/etter.passive.os.fp?rev=HEAD&content-type=text/plain  #
#                                                                          #
############################################################################

0000:_MSS:80:WS:0:0:0:0:A:LT:3Com Access Builder 4000 7.2
0040:_MSS:80:WS:0:0:0:0:A:LT:Gold Card Ethernet Interface Firmware Ver. 3.19 (95.01.16)
0046:_MSS:80:WS:0:0:0:0:A:LT:Cyclades PathRouter
0096:_MSS:80:WS:0:0:0:0:A:LT:Cyclades PathRouter V 1.2.4
0100:_MSS:80:WS:0:0:0:0:A:LT:Allied Telesyn AT-S10 version 3.0 on an AT-TS24TR hub
0100:_MSS:80:WS:0:0:1:0:A:LT:Xyplex Network9000
0200:0000:40:WS:0:0:0:0:S:LT:Linux 2.0.35 - 2.0.37
0200:05B4:40:00:0:0:0:0:S:2C:Linux 2.0.35 - 2.0.38
0200:05B4:40:00:0:0:0:0:S:LT:Linux 2.0.38
0200:05B4:40:34:0:0:0:0:S:LT:Linux 2.0.33
0200:05B4:40:WS:0:0:0:0:S:2C:Linux 2.0.34-38
0200:05B4:40:WS:0:0:0:0:S:LT:Linux 2.0.36
0200:_MSS:80:00:0:0:0:0:A:LT:Linux 2.0.32-34
0200:_MSS:80:00:0:1:0:0:A:LT:Bay Networks BLN-2 Network Router or ASN Processor rev 9
0200:_MSS:80:00:0:1:0:1:A:LT:Bay Networks BLN-2 Network Router or ASN Processor rev 9
0200:_MSS:80:WS:0:0:0:0:A:LT:3COM / USR TotalSwitch Firmware: 02.02.00R
0212:_MSS:80:00:0:0:0:0:A:LT:Linux 2.0.32-34
0212:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7
0212:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7
0212:_MSS:80:WS:0:0:0:0:A:LT:CacheOS (CacheFlow 2000 proxy cache)
0212:_MSS:80:WS:0:0:1:0:A:LT:Linux 2.2.5 - 2.2.13 SMP
0212:_MSS:80:WS:0:1:0:0:A:LT:NetBSD 1.4 running on a SPARC IPX
0212:_MSS:80:WS:0:1:0:1:A:LT:NetBSD 1.4 running on a SPARC IPX
0212:_MSS:80:WS:0:1:1:0:A:LT:NetBSD 1.4 / Generic mac68k (Quadra 610)
0212:_MSS:80:WS:0:1:1:1:A:LT:NetBSD 1.4 / Generic mac68k (Quadra 610)
0218:0218:40:00:0:1:0:1:A:LT:NetBSD
0244:_MSS:80:WS:0:0:0:0:A:LT:Cyclades PathRouter/PC
03CA:_MSS:80:WS:0:0:0:0:A:LT:MPE/iX 5.5
03E0:0550:40:05:1:1:1:1:S:LT:Windows 2000
03F2:_MSS:80:00:0:0:0:0:A:LT:Lexmark Optra S Printer
03F2:_MSS:80:WS:0:0:0:0:A:LT:Lexmark Optra S Printer
03F6:_MSS:80:WS:0:0:0:0:A:LT:Lexmark Optra S Printer
0400:0400:20:WS:0:0:0:0:A:LT:Windows 2000
0400:05B4:FF:WS:0:0:0:0:A:LT:3Com 812 ADSL ROUTER
0400:_MSS:80:00:0:1:0:0:A:LT:Bay Networks BLN-2 Network Router or ASN Processor rev 9
0400:_MSS:80:00:0:1:0:1:A:LT:Bay Networks BLN-2 Network Router or ASN Processor rev 9
0400:_MSS:80:WS:0:0:0:0:A:LT:3com Office Connect Router 810
0400:_MSS:80:WS:0:0:1:0:A:LT:Aironet 630-2400 V3.3P Wireless LAN bridge
0424:_MSS:80:WS:0:0:0:0:A:LT:Intel InBusiness Print Station
0430:_MSS:80:WS:0:0:0:0:A:LT:PacketShaper 4000 v4.1.3b2 2000-04-05
0564:0564:80:WS:1:1:1:0:A:LT:Windows 2000
0578:_MSS:80:WS:0:0:0:0:A:LT:Minix 32-bit/Intel 2.0.0
05B4:B405:40:00:0:1:1:1:A:LT:Red Hat 7.1  (kernel 2.4.3)
05B4:B405:80:00:0:1:1:1:A:LT:Windows 2000 Server
05B4:_MSS:80:00:0:1:0:0:A:LT:HP JetDirect Card (J4169A) in an HP LaserJet 8150
05B4:_MSS:80:WS:0:0:0:0:A:LT:TOPS-20 Monitor 7(102540)-1,TD-1
05B4:_MSS:80:WS:0:1:1:0:A:LT:Network Appliance NetCache 5.1D4
05B4:_MSS:80:WS:0:1:1:1:A:LT:Network Appliance NetCache 5.1D4
05DC:_MSS:80:WS:0:0:0:0:A:LT:Gandalf LanLine Router
0600:_MSS:80:WS:0:0:0:0:A:LT:Chase IOLAN Terminal Server v3.5.02 CDi
0640:_MSS:80:WS:0:0:0:0:A:LT:APC MasterSwitch Network Power Controller
0648:_MSS:80:WS:0:0:0:0:A:LT:FastComm FRAD F9200-DS-DNI -- Ver. 4.2.3A
06C2:_MSS:80:WS:0:0:0:0:A:LT:Cyclades PathRAS Remote Access Server v1.1.8 - 1.3.12
0700:_MSS:80:00:0:0:0:0:A:LT:Lantronix ETS16P Version V3.5/2(970721)
0700:_MSS:80:WS:0:0:0:0:A:LT:Lantronix ETS16P Version V3.5/2(970721)
073F:_MSS:80:00:0:0:0:0:A:LT:Novell NetWare 3.12 or 386 TCP/IP
073F:_MSS:80:WS:0:0:0:0:A:LT:CLIX R3.1 Vr.7.6.20 6480
07D0:_MSS:80:00:0:0:1:0:A:LT:Novell NetWare 3.12 - 5.00
07D0:_MSS:80:WS:0:0:1:0:A:LT:Novell NetWare 3.12 - 5.00
0800:_MSS:80:00:0:0:0:0:A:LT:KA9Q
0800:_MSS:80:00:0:0:0:1:A:LT:KA9Q
0800:_MSS:80:WS:0:0:0:0:A:LT:3Com Access Builder 4000 7.2
0800:_MSS:80:WS:0:0:1:0:A:LT:HP Procurve Routing Switch 9304M
0808:_MSS:80:WS:0:0:0:0:A:LT:Siemens HICOM 300 Phone switch (WAML LAN card)
0848:_MSS:80:WS:0:0:0:0:A:LT:Intergraph Workstation (2000 Series) running CLiX R3.1
0860:0218:40:00:1:1:1:0:S:30:Windows 9x
0860:0218:40:00:1:1:1:0:S:3C:Windows 9x
0860:0218:40:00:1:1:1:0:S:LT:Windows 9x
0860:0218:FF:WS:0:0:0:0:S:LT:Cisco IGS 3000 IOS 11.x(16), 2500 IOS 11.2(3)P
0860:05B4:FF:WS:0:0:0:0:A:LT:IOS Version 10.3(15) - 11.1(20)
0860:_MSS:80:00:0:0:0:0:A:LT:HP JetDirect  Firmware Rev. H.06.00
0860:_MSS:80:00:0:1:1:0:A:LT:Windows NT4 / Win95 / Win98
0860:_MSS:80:00:0:1:1:1:A:LT:Windows NT4 / Win95 / Win98
0860:_MSS:80:WS:0:0:0:0:A:LT:Chase IOLan Terminal Server
0A28:_MSS:80:WS:0:0:0:0:A:LT:Apple Color LaserWrite 600 Printer
0B63:_MSS:80:00:0:1:1:0:A:LT:Linux 2.1.19 - 2.2.17
0B63:_MSS:80:00:0:1:1:1:A:LT:Linux 2.1.19 - 2.2.17
0B68:05B4:FF:WS:1:1:1:0:A:LT:Lexmark T520 Network Printer
0B68:_MSS:40:WS:0:0:1:0:A:LT:Linux 2.0.32 - 2.0.34
0B68:_MSS:80:00:0:1:1:0:A:LT:Sun Solaris 8 early acces beta through actual release
0B68:_MSS:80:00:0:1:1:1:A:LT:Sun Solaris 8 early acces beta through actual release
0B68:_MSS:80:WS:0:0:0:0:A:LT:D-Link Print Server
0BB8:_MSS:80:00:0:1:0:0:A:LT:OpenVMS 7.1 Alpha running Digital's UCX v4.1ECO2
0C00:_MSS:40:WS:0:0:0:0:S:LT:Linux Slakware 8.0
0C00:_MSS:80:WS:0:0:0:0:A:LT:Canon photocopier/fax/scanner/printer GP30F
0C90:_MSS:80:WS:0:0:0:0:A:LT:HP JetDirect Print Server
0E00:_MSS:80:WS:0:0:0:0:A:LT:Lantronix EPS1 Version V3.5/1(970325)
0F87:_MSS:80:00:0:0:0:0:A:LT:Novell NetWare 3.12 or 386 TCP/IP
0F87:_MSS:80:WS:0:0:0:0:A:LT:A/UX 3.1.1 SVR2 or OpenStep 4.2
0F87:_MSS:80:WS:0:0:1:0:A:LT:AIX 4.3
0FA0:_MSS:80:WS:0:0:0:0:A:LT:MultiTech CommPlete (modem server) RAScard
1000:0200:40:WS:0:0:0:0:S:LT:CISCO IOS
1000:0400:1E:F5:0:0:0:0:S:LT:Alcatel (Xylan) OmniStack 5024 v3.4.5
1000:0400:1E:WS:0:0:0:0:S:LT:Chorus MiX V.3.2 r4.1.5 COMP-386
1000:0400:20:F5:0:0:0:0:S:LT:Alcatel (Xylan) OmniStack 5024
1000:0901:40:10:0:1:0:1:S:LT:Mac os X 10.1
1000:_MSS:20:WS:0:0:0:0:A:LT:Motorola SurfBoard SB4100 CableModem
1000:_MSS:40:WS:0:0:0:0:A:LT:SCO UnixWare 2.1.2
1000:_MSS:40:WS:0:0:0:0:S:LT:Linux
1000:_MSS:80:00:0:0:1:0:A:LT:OpenVMS/Alpha 7.1 using Process Software's TCPWare V5.3-4
1000:_MSS:80:00:0:1:0:0:A:LT:Alcatel 1000 ADSL (modem)
1000:_MSS:80:00:0:1:0:1:A:LT:Alcatel 1000 ADSL (modem)
1000:_MSS:80:WS:0:0:0:0:A:LT:Aironet AP4800E v8.07 11 Mbps wireless access poinit
1000:_MSS:80:WS:0:0:1:0:A:LT:VirtualAccess LinxpeedPro 120 running Software 7.4.33CM
1020:0218:FF:WS:0:0:0:0:A:LT:Cisco 2600 IOS 12.0
1020:022C:FF:00:0:0:0:0:S:LT:Cisco 1750 IOS 12.0(5), Cisco 2500 IOS 11.3(1)
1020:05B4:FF:WS:0:0:0:0:S:LT:Cisco 2611 IOS 11.3(2)XA4
1020:_MSS:80:WS:0:0:0:0:A:LT:AS5200
1020:_MSS:FF:WS:0:0:1:0:A:LT:Cisco IOS
10C0:0218:FF:WS:0:0:0:0:S:LT:Cisco 1600 IOS 11.2(15)P
10C0:05B4:80:WS:1:1:1:0:S:30:Windows NT SP3
10C0:05B4:FF:WS:0:0:0:0:S:LT:Cisco 3620 IOS 11.2(17)P
10C0:_MSS:80:WS:0:0:0:0:A:LT:Cisco 1600/3640/7513 Router (IOS 11.2(14)P)
111C:05B4:40:WS:0:0:1:0:A:LT:SCO Openserver 502
111C:_MSS:80:WS:0:0:0:0:A:LT:Ascend/Lucent Max (HP,4000-6000) version 6.1.3 - 7.0.2+
111C:_MSS:80:WS:0:0:1:0:A:LT:Apple LaserWriter 16/600 PS, HP 6P, or HP 5 Printer
14F0:0218:80:WS:1:1:1:0:A:LT:Windows 2000 Professional
159F:05B4:40:00:0:1:1:0:S:3C:FreeBSD 2.2.1 - 4.1
165C:_MSS:80:WS:0:0:1:0:A:LT:SCO Release 5
1680:_MSS:80:00:0:1:1:1:A:LT:Linux 2.4.7 (X86)
16A0:0578:40:00:1:1:1:1:A:LT:Linux 2.4.7
16A0:05B4:40:00:0:1:1:1:A:LT:Linux 2.4.4-4GB
16A0:05B4:40:00:1:1:1:0:A:LT:Linux 2.4.2
16A0:05B4:40:00:1:1:1:1:A:3C:Linux 2.4.0 - Linux 2.4.17
16A0:05B4:40:01:1:1:1:1:A:LT:Linux Kernel 2.4.17 (with MOSIX patch)
16A0:05B4:80:00:1:1:1:1:A:3C:Linux Kernel 2.4.12
16A0:05B4:FF:00:1:1:1:1:A:3C:Linux 2.4.12
16A0:_MSS:80:00:0:1:1:0:A:LT:Linux Kernel 2.4.0 - 2.4.17 (X86)
16A0:_MSS:80:00:0:1:1:1:A:LT:Linux Kernel 2.4.0 - 2.4.17 (X86)
16B0:0584:40:WS:1:1:1:0:A:LT:Redhat 7.0 (linux 2.2.16)
16B0:05AC:40:00:1:1:1:0:S:3C:Linux 2.4.10
16B0:05AC:40:6F:1:1:1:0:S:3C:Linux 2.4.10
16D0:0218:80:00:1:1:1:0:S:30:Windows 95
16D0:05B4:20:00:1:1:1:1:S:LT:Linux 2.4.10-GR Security Patch 1.8.1
16D0:05B4:40:00:0:1:1:0:A:LT:Linux Slackware 8
16D0:05B4:40:00:0:1:1:0:S:3C:Linux 2.4.13-ac7
16D0:05B4:40:00:1:1:1:0:A:LT:Linux 2.4.0 - Linux 2.4.17
16D0:05B4:40:00:1:1:1:0:S:30:Linux 2.4.1-14
16D0:05B4:40:00:1:1:1:0:S:34:Linux 2.4.1-14
16D0:05B4:40:00:1:1:1:0:S:3C:Linux 2.4.0 - Linux 2.4.17
16D0:05B4:40:00:1:1:1:1:S:3C:Linux 2.4.0 - Linux 2.4.17
16D0:05B4:40:01:1:1:1:1:S:LT:Linux 2.4.16
16D0:05B4:40:WS:0:0:0:0:A:LT:HP JetDirect
16D0:05B4:40:WS:0:0:1:0:A:LT:Linux 2.4.0 - Linux 2.4.17
16D0:05B4:40:WS:1:1:1:0:A:30:Linux 2.4.0 - Linux 2.4.17
16D0:05B4:80:00:1:1:1:1:S:LT:Linux 2.4.14 - 2.4.17
16D0:05B4:80:WS:1:1:1:0:S:30:Windows 95
16D0:05B4:80:WS:1:1:1:0:S:LT:Windows 98
16D0:05B4:FF:WS:1:1:1:0:A:LT:Linux 2.4.10
16D0:B405:40:00:1:1:1:1:S:LT:Redhat Linux 7.1 (Kernel 2.4.2)
16D0:B405:40:WS:0:0:0:0:A:LT:SMC Broadband / MacSense Router
16D0:_MSS:80:00:0:0:0:0:A:LT:HP Color LaserJet 4500N, Jet Direct J3113A/2100
16D0:_MSS:80:00:0:1:1:0:A:LT:Windows NT4 / Win95 / Win98
16D0:_MSS:80:00:0:1:1:1:A:LT:Windows NT4 / Win95 / Win98
16D0:_MSS:80:WS:0:0:0:0:A:LT:HP Color LaserJet 4500N, Jet Direct J3113A/2100
16D0:_MSS:80:WS:0:0:1:0:A:LT:Linux 2.4.7 (X86)
1800:0558:80:WS:0:0:1:0:A:LT:Novell Netware 5.1 SP3
1800:05B4:80:WS:0:0:1:0:A:LT:Novell Netware 4.0
1800:5805:80:WS:0:0:1:0:A:LT:Novell Netware 5.1
1800:_MSS:40:WS:0:0:1:0:A:LT:VMS MultiNet V4.2(16) / OpenVMS V7.1-2
1800:_MSS:80:00:0:1:0:0:A:LT:OpenVMS 6.2 - 7.2-1 on VAX or AXP
1800:_MSS:80:00:0:1:0:1:A:LT:OpenVMS 6.2 - 7.2-1 on VAX or AXP
1800:_MSS:80:00:0:1:1:0:A:LT:VMS MultiNet V4.2(16)/ OpenVMS V7.1-2
1800:_MSS:80:00:0:1:1:1:A:LT:VMS MultiNet V4.2(16)/ OpenVMS V7.1-2
1800:_MSS:80:WS:0:0:0:0:A:LT:IPAD Model 5000 or V.1.52
1800:_MSS:80:WS:0:0:1:0:A:LT:Novell Netware 5.0 SP5
192F:_MSS:80:00:0:0:0:0:A:LT:Mac OS 7.0-7.1 With MacTCP 1.1.1 - 2.0.6
192F:_MSS:80:WS:0:0:0:0:A:LT:Mac OS 7.0-7.1 With MacTCP 1.1.1 - 2.0.6
1AB8:0564:40:WS:1:1:1:0:A:LT:IRIX
1C84:_MSS:80:WS:0:0:0:0:A:LT:Instant Internet box
1D4C:_MSS:80:WS:0:0:0:0:A:LT:Sega Dreamcast
1F0E:_MSS:80:WS:0:0:0:0:A:LT:AmigaOS AmiTCP/IP 4.3
1FFF:_MSS:80:00:0:0:1:0:A:LT:Novell NetWare 3.12 - 5.00
1FFF:_MSS:80:WS:0:0:1:0:A:LT:NetWare 4.11 SP7- 5 SP3A BorderManager 3.5
2000:0002:40:00:0:1:0:0:A:LT:Mac OS 9/Apple ShareIP
2000:0109:40:WS:0:0:0:0:A:LT:Cisco CacheOS 1.1.0
2000:0200:40:WS:0:0:0:0:A:LT:QNX / Amiga OS
2000:020C:40:00:0:1:0:1:A:LT:OS/400
2000:0218:40:WS:0:0:0:0:A:LT:OS/400
2000:0218:80:00:1:1:1:0:S:30:Windows 9x
2000:0218:80:WS:1:1:1:0:S:30:Windows 9x or 2000
2000:0550:80:WS:1:1:1:0:S:30:Windows 9x
2000:0586:80:WS:1:1:1:0:S:30:Windows 9x or NT4
2000:05B0:20:WS:0:0:1:0:S:LT:Windows 95
2000:05B0:80:00:1:1:1:0:S:40:Linux 2.2.13
2000:05B0:80:00:1:1:1:1:S:LT:Windows 95
2000:05B0:80:WS:1:1:1:0:S:30:Windows NT SP3
2000:05B4:20:00:0:0:1:0:S:2C:Windows NT 4.0
2000:05B4:20:WS:0:0:1:0:S:LT:Windows 95
2000:05B4:20:WS:1:1:0:0:S:LT:Slackware Linux 7.1 Kernel 2.2.16
2000:05B4:40:00:0:1:1:0:S:3C:BSDI BSD/OS 3.1
2000:05B4:40:00:0:1:1:0:S:LT:BSDI BSD/OS 3.1
2000:05B4:40:00:1:1:1:0:S:3C:BSDI BSD/OS 3.0-3.1 (or MacOS, NetBSD)
2000:05B4:40:00:1:1:1:0:S:40:WebTV netcache engine (BSDI)
2000:05B4:40:WS:0:0:0:0:S:2C:CacheFlow 500x CacheOS 2.1.08 - 2.2.1
2000:05B4:40:WS:0:0:1:0:S:2C:AXCENT Raptor Firewall Windows NT 4.0/SP3
2000:05B4:80:00:0:0:1:0:S:2C:Windows NT 4.0
2000:05B4:80:00:0:0:1:0:S:LT:Windows NT 4.0
2000:05B4:80:00:1:1:1:0:S:2C:Windows 9x
2000:05B4:80:00:1:1:1:0:S:30:Windows 9x
2000:05B4:80:00:1:1:1:0:S:40:Windows 9x
2000:05B4:80:00:1:1:1:1:S:40:Windows 95
2000:05B4:80:WS:0:0:1:0:S:LT:Windows NT 4.0
2000:05B4:80:WS:1:0:1:0:S:2C:Windows NT
2000:05B4:80:WS:1:0:1:0:S:LT:Windows NT
2000:05B4:80:WS:1:1:0:0:S:30:Windows 95
2000:05B4:80:WS:1:1:1:0:S:30:Windows 98 / 2000
2000:05B4:80:WS:1:1:1:0:S:3C:Linux 2.2.19
2000:6363:80:WS:1:1:1:0:S:LT:Microsoft NT 4.0 Server SP5
2000:B405:80:WS:0:0:1:0:S:LT:Windows 98 / NT
2000:B405:80:WS:1:1:1:0:S:LT:Windows 98
2000:_MSS:40:WS:0:0:0:0:S:LT:Mac OS 8.6
2000:_MSS:40:WS:0:0:1:0:A:LT:BSDI BSD/OS
2000:_MSS:80:00:0:0:0:0:A:LT:IBM VM/ESA 2.2.0 CMS Mainframe System
2000:_MSS:80:00:0:0:1:0:A:LT:Novell NetWare 3.12 - 5.00
2000:_MSS:80:00:0:1:0:0:A:LT:Accelerated Networks - High Speed Integrated Access VoDSL
2000:_MSS:80:00:0:1:0:1:A:LT:Tandem NSK D40
2000:_MSS:80:00:0:1:1:0:A:LT:AS/400e 720 running OS/400 R4.4
2000:_MSS:80:00:0:1:1:1:A:LT:AS/400e 720 running OS/400 R4.4
2000:_MSS:80:WS:0:0:0:0:A:LT:AGE Logic, Inc. IBM XStation
2000:_MSS:80:WS:0:0:1:0:A:LT:Windows NT / Win9x
2010:_MSS:80:WS:0:0:1:0:A:LT:Windows NT / Win9x
2017:05B4:40:00:0:1:1:1:A:LT:BSDI BSD/OS 3.0-3.1 (or possibly MacOS, NetBSD)
2017:05B4:80:WS:0:0:1:0:A:LT:Windows 98 SE
2017:_MSS:80:00:0:1:0:0:A:LT:Ascend GRF Router running Ascend Embedded/OS 2.1
2017:_MSS:80:00:0:1:1:0:A:LT:BSDI 4.0-4.0.1
2017:_MSS:80:00:0:1:1:1:A:LT:BSDI 4.0-4.0.1
2017:_MSS:80:WS:0:0:0:0:A:LT:CacheOS (CacheFlow 500-5000 webcache) CFOS 2.1.08 - 2.2.1
2017:_MSS:80:WS:0:0:1:0:A:LT:3Com NetBuilder & NetBuilder II OS v 9.3
2058:0564:80:WS:0:0:1:0:A:LT:Windows 2000
2058:_MSS:80:WS:0:0:1:0:A:LT:Windows NT / Win9x
20D0:0578:80:WS:0:0:1:0:A:LT:Windows NT 4.0
2120:_MSS:80:WS:0:0:1:0:A:LT:Gauntlet 4.0a firewall on Solaris 2.5.1
2180:05B4:80:WS:0:0:1:0:A:LT:Windows
2180:_MSS:20:WS:0:0:1:0:A:LT:Windows NT / Win9x
2180:_MSS:40:WS:0:0:1:0:A:LT:BSDI BSD/OS
2180:_MSS:80:WS:0:0:1:0:A:LT:Windows NT / Win9x
2190:_MSS:20:WS:0:0:1:0:A:LT:Windows NT / Win9x
2190:_MSS:80:WS:0:0:1:0:A:LT:Windows NT / Win9x
21D2:_MSS:80:WS:0:0:1:0:A:LT:Windows NT / Win9x
21F0:05B4:80:WS:0:0:1:0:A:LT:Windows NT 4.0
2200:_MSS:80:00:0:1:0:0:A:LT:Stock OpenVMS 7.1
2200:_MSS:80:00:0:1:0:1:A:LT:Stock OpenVMS 7.1
2200:_MSS:80:00:0:1:1:0:A:LT:OpenVMS 6.2/Alpha
2200:_MSS:80:00:0:1:1:1:A:LT:OpenVMS 6.2/Alpha
2200:_MSS:80:WS:0:0:0:0:A:LT:Linux 2.0.34-38
2220:_MSS:40:WS:0:0:1:0:A:LT:BSDI BSD/OS
2220:_MSS:80:WS:0:0:1:0:A:LT:Windows NT / Win9x
2229:_MSS:80:00:0:0:1:0:A:LT:Solaris 2.5, 2.5.1
2229:_MSS:80:WS:0:0:0:0:A:LT:DG/UX Release R4.11MU02
2229:_MSS:80:WS:0:0:1:0:A:LT:Solaris 2.3 - 2.4
2238:0218:80:WS:1:1:1:0:S:30:Windows 2000 Pro
2238:0550:80:WS:1:1:1:0:S:LT:Linux
2238:0564:FF:00:0:0:1:0:S:2C:Solaris 2.7
2238:05B4:20:WS:0:0:0:0:A:LT:Snap Server (Quantum)
2238:05B4:40:00:0:0:1:0:S:LT:Solaris 2.6
2238:05B4:40:00:0:1:1:1:A:LT:BSDI BSD/OS 3.0
2238:05B4:40:WS:0:0:1:0:A:LT:BSDI BSD/OS 3.0-3.1 (or possibly MacOS, NetBSD)
2238:05B4:80:WS:0:0:0:0:A:LT:Windows NT 4.x
2238:05B4:80:WS:0:0:1:0:A:LT:Windows NT 4.x / Win9x
2238:05B4:80:WS:1:1:1:0:A:LT:Windows 98 / 2000 / XP
2238:05B4:FF:00:0:0:1:0:S:2C:Solaris 2.6 or 2.7
2238:05B4:FF:WS:0:0:1:0:A:LT:Solaris 5.3 / SunOS 2.6 / OpenBSD
2238:05B4:FF:WS:0:0:1:0:S:LT:Solaris 2.7
2238:05B4:FF:WS:0:1:1:0:S:2C:Solaris 2.6 or 2.7
2238:05B4:FF:WS:1:0:1:0:S:2C:Solaris 2.6 - 2.7
2238:B405:80:WS:0:0:1:0:A:LT:Windows 2000
2238:B405:FF:00:0:1:1:0:A:LT:Solaris
2238:B405:FF:WS:0:0:1:0:A:LT:Solaris 2.5.1
2238:_MSS:40:WS:0:0:1:0:A:LT:BSDI BSD/OS
2238:_MSS:80:WS:0:0:0:0:A:LT:HP printer w/JetDirect card
2238:_MSS:80:WS:0:0:1:0:A:LT:Windows 2000 Professional, Build 2128
2238:_MSS:FF:WS:0:0:1:0:A:LT:Solaris 2.6 - 2.7
223F:05B4:FF:WS:0:0:0:0:A:LT:Solaris 2.6
2297:_MSS:80:00:0:1:1:0:A:LT:Raptor Firewall 6 on Solaris 2.6
2297:_MSS:80:00:0:1:1:1:A:LT:Raptor Firewall 6 on Solaris 2.6
2328:_MSS:FF:WS:0:0:1:0:A:LT:Solaris 2.6 - 2.7
2332:_MSS:80:00:0:0:1:0:A:LT:Solaris 2.3 - 2.4
2332:_MSS:80:WS:0:0:0:0:A:LT:Solaris 2.4 w/most Sun patches
2332:_MSS:80:WS:0:0:1:0:A:LT:Solaris 2.3 - 2.4
239C:_MSS:80:WS:0:0:0:0:A:LT:Apollo Domain/OS SR10.4
23B4:23B4:FF:00:0:0:1:0:S:LT:Solaris 2.6
2400:_MSS:FF:WS:0:0:1:0:A:LT:Solaris 2.6 - 2.7
2491:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7 with tcp_strong_iss=0
2491:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7 with tcp_strong_iss=0
2530:05B4:80:WS:0:0:1:0:A:LT:Windows 2000
2544:_MSS:80:00:0:0:1:0:A:LT:Solaris 2.3 - 2.4
25BC:0564:FF:WS:0:0:1:0:A:LT:Solaris
2648:8405:FF:00:0:1:1:1:A:LT:Solaris
2756:_MSS:80:WS:0:0:0:0:A:LT:AmigaOS AmiTCP/IP Genesis 4.6
2788:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7
2788:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7
2798:05B4:FF:00:0:1:1:0:A:LT:Solaris
2798:05B4:FF:00:0:1:1:1:A:LT:Solaris 2.6 / SunOS 5.6
2798:05B4:FF:00:1:1:1:1:A:LT:SunOS 5.7
2798:B405:FF:00:0:1:1:1:A:LT:RedHat 7.1 (linux 2.4.2)
2798:_MSS:FF:WS:0:0:1:0:A:LT:Solaris 2.6 - 2.7
2D24:_MSS:80:00:0:1:1:1:A:LT:Linux Kernel 2.4.0 - 2.4.17 (X86)
2D25:_MSS:80:WS:0:0:0:0:A:LT:Mac OS 7.0-7.1 With MacTCP 1.1.1 - 2.0.6
2DA0:_MSS:80:WS:0:0:0:0:A:LT:Windows 98SE + IE5.5sp1
3000:05B4:FF:WS:0:0:0:0:S:2C:BeOS 5.0
3000:05B4:FF:WS:0:1:0:0:S:2C:BeOS 5.0
3000:_MSS:80:WS:0:0:0:0:A:LT:Acorn Risc OS 3.6 (Acorn TCP/IP Stack 4.07)
37FF:_MSS:80:WS:0:0:0:0:A:LT:Linux 1.2.13
3C00:_MSS:80:WS:0:0:0:0:A:LT:Linux 2.0.27 - 2.0.30
3C0A:_MSS:80:00:0:1:1:0:A:LT:Linux 2.1.19 - 2.2.17
3C0A:_MSS:80:00:0:1:1:1:A:LT:Linux 2.1.19 - 2.2.17
3E43:_MSS:80:00:0:1:0:0:A:LT:AIX 4.1-4.1.5
3E43:_MSS:80:00:0:1:0:1:A:LT:AIX 4.1-4.1.5
3E64:05AC:40:00:1:1:1:0:S:3C:Windows 98
3E64:05AC:40:00:1:1:1:1:A:LT:Linux 2.2.x
3E80:_MSS:80:WS:0:0:0:0:A:LT:Alcatel Advanced Reflexes IP Phone, Version: E/AT400/46.8
3E80:_MSS:80:WS:0:0:1:0:A:LT:VersaNet ISP-Accelerator(TM) Remote Access Server
3EBC:05B4:40:00:1:1:1:0:S:3C:Debian/Caldera Linux 2.2.x
3EBC:05B4:40:00:1:1:1:1:A:LT:Linux 2.2.19
3EBC:05B4:40:00:1:1:1:1:S:LT:Linux 2.2.16
3EBC:05B4:40:WS:0:0:0:0:A:LT:AIX 4.3.2
3EBC:05B4:40:WS:0:0:1:0:A:LT:Debian GNU/Linux
3EBC:05B4:40:WS:1:1:1:0:A:LT:Linux 2.2.19
3EBC:B405:40:00:1:1:1:1:S:LT:Slackware Linux v7.1 - Linux Kernel 2.2.16
3EBC:_MSS:40:WS:0:0:1:0:A:LT:AIX 4.02.0001.0000, AIX 4.2
3ED0:0218:40:WS:0:0:1:0:A:LT:Linux
3F25:_MSS:80:00:0:1:0:0:A:LT:AIX 4.3.2.0-4.3.3.0 on an IBM RS/*
3F25:_MSS:80:00:0:1:0:1:A:LT:AIX 4.3.2.0-4.3.3.0 on an IBM RS/*
3F25:_MSS:80:00:0:1:1:0:A:LT:Linux 2.1.19 - 2.2.17
3F25:_MSS:80:00:0:1:1:1:A:LT:Linux 2.1.19 - 2.2.17
3F25:_MSS:80:WS:0:0:0:0:A:LT:AIX 3.2
3F25:_MSS:80:WS:0:0:1:0:A:LT:Linux 2.2.19
3FE0:05B4:40:WS:0:0:0:0:A:LT:Caldera OpenLinux(TM) 1.3
3FE0:_MSS:80:00:0:0:0:0:A:LT:Linux 2.0.32-34
3FF0:_MSS:80:00:0:0:0:0:A:LT:Linux 2.0.34-38
3FF0:_MSS:80:WS:0:0:0:0:A:LT:AtheOS ( www.atheos.cx )
3FFF:_MSS:80:WS:0:0:0:0:A:LT:IBM MVS (unknown version)
4000:0000:40:WS:0:0:0:0:S:LT:ULTRIX V4.5 (Rev. 47)
4000:0200:40:00:0:0:0:0:S:2C:AIX 3.2, 4.2 - 4.3
4000:0200:40:00:0:1:0:0:S:3C:OpenBSD 2.6-2.8
4000:0200:40:00:0:1:0:1:A:LT:IPSO 3.3-FCS
4000:0200:40:00:0:1:0:1:S:LT:OpenBSD
4000:0200:40:00:1:1:0:1:S:LT:FreeBSD
4000:0200:40:WS:0:0:0:0:A:LT:AIX
4000:0200:40:WS:0:0:0:0:S:LT:BorderWare 5.2
4000:0218:80:00:1:1:1:1:S:LT:Windows XP Home
4000:023C:40:00:1:1:1:0:S:40:OpenBSD 3.0
4000:023C:80:WS:1:1:1:0:S:30:Windows NT SP4+
4000:04F8:80:WS:1:1:1:0:S:30:Windows NT SP3
4000:0550:80:WS:1:1:1:0:S:30:Windows 2000
4000:0586:80:WS:1:1:1:0:S:30:Windows 2000
4000:05A0:80:WS:1:1:1:0:S:30:Windows XP Pro
4000:05AC:80:WS:1:1:1:0:S:30:Windows 2000
4000:05B4:40:00:0:0:1:0:S:2C:FreeBSD 4.0-STABLE, 3.2-RELEASE
4000:05B4:40:00:0:1:0:0:S:3C:NetBSD 1.3/i386
4000:05B4:40:00:0:1:1:0:S:2C:FreeBSD 2.2.8-RELEASE
4000:05B4:40:00:0:1:1:0:S:3C:Linux 2.4.2 - 2.4.14
4000:05B4:40:00:0:1:1:0:S:44:FreeBSD 4.3 - 4.4PRERELEASE
4000:05B4:40:00:0:1:1:0:S:LT:FreeBSD 2.2.8-RELEASE
4000:05B4:40:00:0:1:1:1:S:LT:FreeBSD 4.4
4000:05B4:40:00:1:1:1:1:S:LT:OpenBSD 3.0
4000:05B4:40:5E:0:1:1:0:S:2C:FreeBSD 4.0-STABLE, 3.2-RELEASE
4000:05B4:40:62:0:0:1:0:S:2C:FreeBSD 4.0-STABLE, 3.2-RELEASE
4000:05B4:40:70:0:0:1:0:S:2C:FreeBSD 4.0-STABLE, 3.2-RELEASE
4000:05B4:40:WS:0:0:0:0:S:LT:AIX 4.3-4.3.3
4000:05B4:40:WS:0:0:1:0:S:LT:FreeBSD 4.2
4000:05B4:80:00:1:1:1:0:S:30:Windows 2000
4000:05B4:80:4B:1:1:1:0:S:30:Windows ME
4000:05B4:80:WS:1:1:0:0:S:LT:Windows 2000 / BeOS
4000:05B4:80:WS:1:1:1:0:S:30:Windows 2000
4000:05B4:80:WS:1:1:1:0:S:3C:Linux RedHat 7.2 (kernel 2.4.9)
4000:05B4:80:WS:1:1:1:0:S:LT:Windows XP / 2000 / ME
4000:05B4:FF:00:0:1:1:0:S:LT:FreeBSD 2.2.6-RELEASE
4000:05B4:FF:WS:0:0:0:0:A:LT:Cisco Systems IOS 11.3
4000:62BB:80:WS:1:1:1:0:S:LT:Windows 2000
4000:B405:40:00:0:1:1:1:S:LT:FreeBSD
4000:B405:80:WS:1:1:1:0:S:LT:Microsoft Windows 2000 / Mac OS X
4000:D84A:80:WS:1:1:1:0:S:30:Windows 2000
4000:_MSS:40:WS:0:0:0:0:A:LT:NetBSD 1.3 - 1.33 / AIX 4.3.X
4000:_MSS:80:00:0:0:0:0:A:LT:IBM MVS (unknown version)
4000:_MSS:80:00:0:0:1:0:A:LT:OpenVMS 7.1 using Process Software's TCPWare 5.3
4000:_MSS:80:00:0:1:0:0:A:LT:Check Point FireWall-1 4.0 SP-5 (IPSO build)
4000:_MSS:80:00:0:1:0:1:A:LT:Check Point FireWall-1 4.0 SP-5 (IPSO build)
4000:_MSS:80:00:0:1:1:1:A:LT:Linux Kernel 2.4.0 - 2.4.17 (X86)
4000:_MSS:80:WS:0:0:0:0:A:LT:Auspex Fileserver (AuspexOS 1.9.1/SunOS 4.1.4)
4000:_MSS:80:WS:0:0:1:0:A:LT:AmigaOS Miami 3.0
402E:05B4:80:00:0:1:1:1:A:LT:Windows 2000 Professional
402E:_MSS:80:00:0:1:0:0:A:LT:FreeBSD 2.1.0 - 2.1.5
402E:_MSS:80:00:0:1:0:1:A:LT:FreeBSD 2.1.0 - 2.1.5
402E:_MSS:80:00:0:1:1:0:A:LT:D-Link DI-701, Version 2.22
402E:_MSS:80:00:0:1:1:1:A:LT:D-Link DI-701, Version 2.22
402E:_MSS:80:WS:0:0:0:0:A:LT:OpenBSD 2.1/X86
402E:_MSS:80:WS:0:0:1:0:A:LT:AmigaOS Miami 2.1-3.0
402E:_MSS:80:WS:0:1:1:0:A:LT:Windows XP Professional Release
403D:_MSS:80:00:0:1:0:0:A:LT:FreeBSD 2.1.0 - 2.1.5
403D:_MSS:80:00:0:1:0:1:A:LT:FreeBSD 2.1.0 - 2.1.5
403D:_MSS:80:00:0:1:1:0:A:LT:Acorn RiscOS 3.7 using AcornNet TCP/IP stack
403D:_MSS:80:00:0:1:1:1:A:LT:Acorn RiscOS 3.7 using AcornNet TCP/IP stack
4074:_MSS:40:WS:0:0:0:0:A:LT:OpenBSD 2.x
4088:05B4:40:WS:0:0:1:0:A:LT:FreeBSD
40B0:05B4:40:WS:0:0:1:0:A:LT:FreeBSD 4.3
40E8:0218:80:WS:1:1:1:0:A:LT:Windows ME
40E8:05B4:FF:00:0:0:1:0:S:30:Mac OS 7.x-9.x
4150:_MSS:40:WS:0:0:1:0:A:LT:Cisco Localdirector 430, running OS 2.1
4230:0584:80:WS:1:1:1:0:A:LT:Windows 2000
4240:_MSS:80:00:0:0:1:0:A:LT:MacOS 8.1
43E0:05B4:40:00:0:1:0:1:A:LT:OpenBSD 2.8 GENERIC
43E0:05B4:40:00:0:1:1:0:A:LT:FreeBSD 4.x
43E0:05B4:40:00:0:1:1:1:A:LT:FreeBSD 4.4-Release
43E0:05B4:40:00:1:1:1:1:A:LT:OpenBSD 2.9 3.0
43E0:A805:40:00:0:1:0:1:A:LT:OpenBSD 2.6
43E0:_MSS:40:WS:0:0:0:0:A:LT:OpenBSD 2.x
43E0:_MSS:40:WS:0:0:1:0:A:LT:FreeBSD 2.2.1 - 4.0
4410:05AC:80:00:1:1:1:1:A:LT:Windows 2000 Professional
4410:05AC:80:00:1:1:1:1:A:LT:Windows 2000 Server
4410:05AC:80:WS:1:1:1:0:A:LT:Windows 2000 Workstation
4431:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7
4431:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7
4440:05B4:80:WS:1:1:1:0:A:LT:Solaris 7
4452:_MSS:80:00:0:0:1:0:A:LT:Solaris 2.5, 2.5.1
4470:05B4:40:00:1:1:0:0:A:LT:Windows 2000
4470:05B4:40:00:1:1:1:1:A:LT:Windows NT
4470:05B4:40:WS:0:0:1:0:A:LT:FreeBSD 4.2
4470:05B4:40:WS:1:1:0:0:A:LT:OpenBSD 2.8
4470:05B4:80:00:0:1:1:0:A:LT:Windows 2000
4470:05B4:80:00:1:1:0:1:A:LT:Windows 2000 Professional
4470:05B4:80:00:1:1:1:0:A:LT:Windows 2000 Professional
4470:05B4:80:00:1:1:1:1:A:LT:Windows 2000 Professional
4470:05B4:80:WS:0:0:1:0:A:LT:Windows 2000
4470:05B4:80:WS:1:1:1:0:A:LT:FreeBSD 4.x / Windows 2000
4470:B405:80:00:0:1:1:1:A:LT:Windows 2000 Workstation
4470:B405:FF:00:0:0:1:0:A:LT:Mac OS 8.6
4470:_MSS:40:WS:0:0:0:0:A:LT:FreeBSD 2.2.1 - 4.0
4470:_MSS:40:WS:0:0:1:0:A:LT:FreeBSD 2.2.1 - 4.0
4470:_MSS:80:00:0:1:1:0:A:LT:Windows NT4 / Win95 / Win98
4470:_MSS:80:00:0:1:1:1:A:LT:Windows NT4 / Win95 / Win98
4470:_MSS:80:WS:0:0:0:0:A:LT:Snap Network Box
4470:_MSS:80:WS:0:0:1:0:A:LT:Windows 2000 RC1
4510:0550:80:WS:0:0:1:0:A:LT:Windows 2000 Professional 5.0.2195 Service Pack 2
4510:0550:80:WS:1:1:1:0:A:LT:Windows 2000 Professional 5.0.2195 Service Pack 2
455B:_MSS:80:00:0:0:0:0:A:LT:MacOS 8.1 running on a PowerPC G3 (iMac)
455B:_MSS:80:00:0:0:1:0:A:LT:Mac OS 8.6
462B:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 7 X86
462B:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 7 X86
5B40:_MSS:80:WS:0:0:0:0:A:LT:Polycom ViewStation 512K videoconferencing system
6000:_MSS:80:00:0:0:0:0:A:LT:SCO OpenServer(TM) Release 5
6000:_MSS:80:00:0:0:1:0:A:LT:OpenVMS v7.1 VAX
6000:_MSS:80:00:0:1:1:0:A:LT:Sequent DYNIX/ptx(R) V4.4.6
6028:05B4:40:00:1:1:1:1:A:LT:Solaris 8
6028:B405:40:00:0:1:1:1:A:LT:Solaris 8
60DA:_MSS:80:00:0:1:1:0:A:LT:Sun Solaris 8 early acces beta through actual release
60DA:_MSS:80:00:0:1:1:1:A:LT:Sun Solaris 8 early acces beta through actual release
60F4:05B4:40:00:0:0:1:0:S:LT:SCO UnixWare 7.0.1
60F4:05B4:40:00:0:1:1:0:S:LT:SCO UnixWare 7.1.0 x86
60F4:05B4:40:WS:1:1:1:0:S:30:SunOS 5.8
60F4:05B4:40:WS:1:1:1:0:S:LT:Solaris 8
60F4:_MSS:40:WS:0:0:1:0:A:LT:SCO OpenServer 5.0.5
60F4:_MSS:80:00:0:1:0:0:A:LT:NCR MP-RAS SVR4 UNIX System Version 3
60F4:_MSS:80:00:0:1:0:1:A:LT:NCR MP-RAS SVR4 UNIX System Version 3
60F4:_MSS:80:00:0:1:1:0:A:LT:NCR MP-RAS 3.01
60F4:_MSS:80:00:0:1:1:1:A:LT:NCR MP-RAS 3.01
60F4:_MSS:80:WS:0:0:0:0:A:LT:SCO UnixWare 7.0.0 or OpenServer 5.0.4-5
61A8:0200:40:00:1:1:1:1:A:LT:Windows NT
61A8:_MSS:80:00:0:1:1:0:A:LT:Windows NT4 / Win95 / Win98
61A8:_MSS:80:00:0:1:1:1:A:LT:Windows NT4 / Win95 / Win98
6FCC:_MSS:80:WS:0:0:0:0:A:LT:IBM OS/2 V 2.1
7000:_MSS:80:WS:0:0:0:0:A:LT:IBM OS/2 V.3
70D5:_MSS:80:00:0:1:1:0:A:LT:Digital UNIX OSF1 V 4.0-4.0F
77C4:05B4:40:00:1:1:1:1:A:LT:Linux SuSE 7.x
77C4:05B4:40:WS:1:1:1:0:A:LT:Linux Mandrake 7.1 / Debian 3.0
77C4:_MSS:40:WS:0:0:1:0:A:LT:Linux 2.1.122 - 2.2.14
7900:_MSS:80:00:0:1:1:0:A:LT:Atari Mega STE running JIS-68k 3.0
7900:_MSS:80:00:0:1:1:1:A:LT:Atari Mega STE running JIS-68k 3.0
7958:0584:40:WS:1:1:1:0:A:LT:Linux 2.2.16-3 (RH 6.2)
7960:0F2C:40:00:1:1:1:0:S:LT:Linux 2.2.12-20
7B2F:_MSS:80:00:0:1:1:0:A:LT:Linux 2.1.19 - 2.2.17
7B2F:_MSS:80:00:0:1:1:1:A:LT:Linux 2.1.19 - 2.2.17
7BC0:_MSS:40:WS:0:0:1:0:A:LT:Linux 2.1.122 - 2.2.14
7BF0:_MSS:40:WS:0:0:1:0:A:LT:Linux 2.1.122 - 2.2.14
7BFC:0564:40:00:1:1:1:1:A:LT:CISCO PIX 6.1
7BFC:0564:40:WS:1:1:1:0:A:LT:Cisco PIX
7C00:_MSS:80:00:0:0:0:0:A:LT:Linux 2.0.27 - 2.0.30
7C00:_MSS:80:WS:0:0:0:0:A:LT:Convex OS Release 10.1
7C38:_MSS:80:00:0:1:1:0:A:LT:Linux 2.1.19 - 2.2.17
7C38:_MSS:80:00:0:1:1:1:A:LT:Linux 2.1.19 - 2.2.17
7C70:05B4:40:00:1:1:1:0:S:LT:Linux 2.3.99-ac - 2.4.0-test1
7C70:_MSS:80:00:0:1:1:0:A:LT:Linux 2.3.28-33
7C70:_MSS:80:00:0:1:1:1:A:LT:Linux 2.3.28-33
7C9C:AA05:40:00:0:1:1:1:A:LT:Linux RedHat 7.1
7CC8:0584:40:00:1:1:1:0:S:3C:Linux 2.2
7D78:0109:80:10:0:1:0:1:S:LT:OpenBSD 2.9 generic
7D78:05B4:20:00:1:1:1:0:S:LT:Linux 2.2.13
7D78:05B4:3A:WS:0:0:0:0:S:LT:Linux 2.0.38
7D78:05B4:40:00:0:1:1:0:S:LT:Linux 2.2.19
7D78:05B4:40:00:0:1:1:1:A:LT:Linux 2.2.17
7D78:05B4:40:00:1:1:0:0:S:LT:Linux 2.2.19
7D78:05B4:40:00:1:1:1:0:A:LT:Linux 2.2.19 - 2.2.20
7D78:05B4:40:00:1:1:1:0:S:3C:Linux 2.2.9 - 2.2.18
7D78:05B4:40:00:1:1:1:0:S:LT:Linux 2.2.14 - 2.2.20
7D78:05B4:40:00:1:1:1:1:A:LT:Linux 2.2.14 - 2.2.20
7D78:05B4:40:00:1:1:1:1:S:LT:Linux 2.2.14 - 2.2.20
7D78:05B4:40:09:1:1:1:0:S:3C:Linux 2.2.x
7D78:05B4:40:BE:1:1:1:0:S:3C:Linux 2.2.16
7D78:05B4:40:WS:0:0:0:0:S:LT:Linux 2.0.33
7D78:05B4:40:WS:0:0:1:0:A:LT:Linux 2.2.19 - 2.2.20
7D78:05B4:40:WS:1:1:1:0:A:LT:Linux 2.2.19 - 2.2.20
7D78:05B4:80:WS:0:0:1:0:A:LT:Windows XP
7D78:05B4:80:WS:1:1:1:0:S:LT:Windows XP Professional
7D78:B405:40:00:1:1:1:1:S:LT:Linux 2.2.14
7D78:_MSS:40:WS:0:0:1:0:A:LT:Linux 2.1.122 - 2.2.14
7E18:_MSS:80:00:0:1:1:0:A:LT:Linux Kernel 2.4.0-test5
7EDC:0584:40:WS:1:1:1:0:A:LT:Linux 2.2.18
7F53:0109:40:00:0:1:1:1:A:LT:Linux 2.2.14br
7F53:_MSS:80:00:0:0:0:0:A:LT:AIX 4.0 - 4.2
7F53:_MSS:80:00:0:1:1:0:A:LT:Linux 2.1.19 - 2.2.17
7F53:_MSS:80:00:0:1:1:1:A:LT:Linux 2.1.19 - 2.2.17
7F53:_MSS:80:WS:0:0:0:0:A:LT:AIX 3.2
7F53:_MSS:80:WS:0:0:1:0:A:LT:Linux Kernel 2.1.88
7F7D:_MSS:80:00:0:1:1:0:A:LT:Linux 2.1.91 - 2.1.103
7F7D:_MSS:80:00:0:1:1:1:A:LT:Linux 2.1.91 - 2.1.103
7F80:0550:40:00:1:1:1:1:A:LT:Linux 2.2.19
7FB6:0218:FF:00:0:0:0:0:S:LT:3Com HiPer ARC, System V4.2.32
7FB8:0218:40:00:1:1:0:0:S:3C:SCO UnixWare 7.1.0 x86
7FB8:0218:40:00:1:1:1:1:A:LT:Linux 2.2.19
7FE0:05B4:40:WS:0:0:0:0:A:LT:Linux 2.0.38
7FE0:_MSS:40:WS:0:0:0:0:A:LT:Linux 2.0.34 - 2.0.38
7FE0:_MSS:80:00:0:0:0:0:A:LT:Linux 2.0.32-34
7FE0:_MSS:80:WS:0:0:0:0:A:LT:Cobalt Linux 4.0 (Fargo) Kernel 2.0.34C52_SK on MIPS
7FF0:_MSS:80:00:0:0:0:0:A:LT:Linux 2.0.34-38
7FFF:05B4:80:00:1:1:1:0:S:LT:Windows XP
7FFF:05B4:80:WS:1:1:1:0:A:Windows 98 SE
7FFF:_MSS:80:00:0:0:1:0:A:LT:Linux 2.4.7 (X86)
7FFF:_MSS:80:00:0:1:0:0:A:LT:ReliantUNIX-Y 5.44 B0033 RM600 1/256 R10000
7FFF:_MSS:80:00:0:1:1:0:A:LT:Linux Kernel 2.4.0 - 2.4.17 (X86)
7FFF:_MSS:80:00:0:1:1:1:A:LT:Linux Kernel 2.4.0 - 2.4.17 (X86)
7FFF:_MSS:80:WS:0:0:0:0:A:LT:SINIX-Y 5.43B0045
7FFF:_MSS:80:WS:0:0:1:0:A:LT:Linux 2.1.76
8000:0200:40:00:0:1:0:0:A:LT:Mac OS X Server
8000:0598:40:00:0:0:0:0:S:LT:??? (PlusGSM, InterNetia proxy)
8000:05B4:20:WS:0:0:1:0:S:2C:Windows CE 3.0 (Ipaq 3670)
8000:05B4:20:WS:0:1:1:0:S:2C:Windows CE 3.0 (Ipaq 3670)
8000:05B4:40:00:0:0:1:0:S:2C:HP-UX B.10.01 A 9000/712
8000:05B4:40:00:0:1:0:0:A:LT:NetBSD
8000:05B4:40:00:0:1:0:0:S:LT:OpenVMS
8000:05B4:40:00:0:1:1:0:A:LT:HP-UX
8000:05B4:40:00:0:1:1:0:S:30:Digital UNIX V4.0E, Mac OS X
8000:05B4:40:00:0:1:1:1:S:LT:MAC OS X 10.1.2
8000:05B4:40:WS:0:0:1:0:A:LT:Mac OS X Darwin 1.4 / HP-UX
8000:05B4:80:00:0:1:1:0:S:30:Dec V4.0 OSF1
8000:05B4:80:WS:0:0:1:0:S:LT:Novell NetWare 4.11
8000:05B4:FF:00:0:1:1:0:S:30:Mac OS 9
8000:05B4:FF:00:0:1:1:1:A:LT:Mac OS
8000:05B4:FF:WS:0:0:1:0:A:LT:OpenBSD
8000:B405:40:00:0:1:1:1:S:LT:Mac OS X 10.x (Darwin 1.3.x 1.4)
8000:B405:FF:00:0:1:0:0:S:LT:Mac OS 9.1
8000:B405:FF:00:0:1:1:0:A:LT:Mac OS 9.x
8000:B405:FF:00:0:1:1:0:S:LT:Mac OS 9.x
8000:B405:FF:00:0:1:1:1:A:LT:Mac OS 9
8000:_MSS:80:00:0:0:1:0:A:LT:Novell NetWare 3.12 - 5.00
8000:_MSS:80:00:0:1:0:0:A:LT:Cray UNICOS 9.0.1ai - 10.0.0.2
8000:_MSS:80:00:0:1:0:1:A:LT:Cray UNICOS 9.0.1ai - 10.0.0.2
8000:_MSS:80:00:0:1:1:0:A:LT:Apple MacOS 9.04 (Powermac or G4)
8000:_MSS:80:00:0:1:1:1:A:LT:Apple MacOS 9.04 (Powermac or G4)
8000:_MSS:80:WS:0:0:0:0:A:LT:DECNIS 600 V4.1.3B System
8000:_MSS:80:WS:0:0:1:0:A:LT:Cisco IOS 12.0(3.3)S  (perhaps a 7200)
805C:_MSS:80:00:0:1:0:0:A:LT:BSDI BSD/OS 2.0 - 2.1
805C:_MSS:80:00:0:1:0:1:A:LT:BSDI BSD/OS 2.0 - 2.1
805C:_MSS:80:00:0:1:1:0:A:LT:Compaq Tru64 UNIX (formerly Digital UNIX) 4.0e
807A:_MSS:80:00:0:1:0:0:A:LT:OpenBSD 2.6-2.8
807A:_MSS:80:00:0:1:0:1:A:LT:OpenBSD 2.6-2.8
807A:_MSS:80:00:0:1:1:0:A:LT:AmigaOS 3.1 running Miami Deluxe 0.9m
807A:_MSS:80:00:0:1:1:1:A:LT:AmigaOS 3.1 running Miami Deluxe 0.9m
81D0:0218:40:00:0:1:0:0:A:LT:OSF1 4.0
81D0:_MSS:40:WS:0:0:1:0:A:LT:Compaq Tru64 UNIX 5.0
8218:05B4:40:00:0:1:1:1:A:LT:SX-Server 10.0.3
8218:05B4:40:01:1:1:1:0:A:LT:Solaris 8
8218:B405:40:00:0:1:1:1:A:LT:MacOS X Server Release
832C:05B4:40:00:0:1:1:0:A:LT:Compaq Tru64 UNIX 5.0
832C:05B4:FF:WS:0:0:1:0:S:2C:Solaris 7
832C:B405:40:WS:0:0:1:0:A:LT:Mac OS X 10.1
832C:_MSS:40:WS:0:0:1:0:A:LT:Linux 2.0.34 - 2.0.38
8371:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7
8371:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7
8377:_MSS:80:00:0:0:1:0:A:LT:Solaris 2.5, 2.5.1
869F:_MSS:80:00:0:1:1:0:A:LT:Windows NT4 / Win95 / Win98
869F:_MSS:80:00:0:1:1:1:A:LT:Windows NT4 / Win95 / Win98
8765:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7 with tcp_strong_iss=0
8765:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7 with tcp_strong_iss=0
879B:_MSS:80:WS:0:0:1:0:A:LT:Solaris 2.5, 2.5.1
87C0:_MSS:FF:WS:0:0:1:0:A:LT:Solaris 2.6 - 2.7
88E0:05B4:80:WS:1:1:1:0:S:LT:Windows 2000
8EDA:_MSS:80:00:0:0:1:0:A:LT:Solaris 2.5, 2.5.1
8F4D:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7
8F4D:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7
ABCD:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7
ABCD:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7
AC00:05AC:80:WS:1:1:1:0:S:30:Windows 2000 SP2
AC00:FA3B:80:WS:1:1:1:0:S:LT:Windows 2000 SP2
B270:05B4:80:WS:1:1:1:0:S:LT:Windows ME
B400:05B4:20:03:1:1:0:1:S:LT:Windows 2000 SP2
B5C9:_MSS:80:00:0:1:1:0:A:LT:Windows Millenium Edition v4.90.3000
B5C9:_MSS:80:00:0:1:1:1:A:LT:Windows Millenium Edition v4.90.3000
BB80:_MSS:80:WS:0:0:1:0:A:LT:Windows 98
C000:05B4:40:00:0:0:0:0:S:2C:IRIX 6.5 / 6.4
C000:05B4:40:00:1:1:1:1:A:LT:IRIX 6.5
C000:05B4:40:WS:0:0:0:0:S:LT:Irix 6.5
C000:_MSS:80:00:0:1:0:0:A:LT:IRIX 6.2 - 6.5
C000:_MSS:80:00:0:1:0:1:A:LT:IRIX 6.2 - 6.5
C000:_MSS:80:WS:0:0:0:0:A:LT:OS-9/68K V2.4 (Quanterra Q4124 - 68030)
C08A:_MSS:80:00:0:1:1:0:A:LT:FreeBSD 2.2.1 - 4.1
C08A:_MSS:80:00:0:1:1:1:A:LT:FreeBSD 2.2.1 - 4.1
C0B7:_MSS:80:00:0:1:1:0:A:LT:FreeBSD 2.2.1 - 4.1
C0B7:_MSS:80:00:0:1:1:1:A:LT:FreeBSD 2.2.1 - 4.1
CDFF:_MSS:80:00:0:0:1:0:A:LT:SONY NEWS-OS 6.1.2
E640:05B4:40:02:1:1:0:0:S:LT:Windows 2000 SP2
E920:_MSS:80:00:0:1:1:1:A:LT:Windows ME
EA60:05DC:40:WS:0:0:1:0:A:LT:Cisco 667i-DIR DSL router -- cbos 2.4.2
EA60:_MSS:80:WS:0:0:1:0:A:LT:Cisco 675 DSL router -- cbos 2.1
EBC0:05B4:40:02:1:1:0:0:S:LT:Windows ME
ED90:_MSS:40:WS:0:0:1:0:A:LT:IRIX 6.2 - 6.5
EE48:_MSS:40:WS:0:0:1:0:A:LT:IRIX 5.1 - 5.3
EF2A:_MSS:80:00:0:1:0:0:A:LT:IRIX 5.2
EF2A:_MSS:80:00:0:1:0:1:A:LT:IRIX 5.2
EF88:_MSS:40:WS:0:0:1:0:A:LT:IRIX 6.2 - 6.5
F000:0200:40:WS:0:0:0:0:S:LT:IRIX 5.3 / 4.0.5F
F000:05B4:40:00:0:1:0:0:S:LT:OSF1 5.1
F000:05B4:40:WS:0:0:0:0:S:LT:IRIX 6.3
F000:05B4:40:WS:1:1:0:0:S:LT:IRIX 6.5.10
F000:_MSS:80:00:0:1:0:0:A:LT:IRIX 5.3
F000:_MSS:80:00:0:1:0:1:A:LT:IRIX 5.3
F99F:0000:80:WS:0:0:0:0:S:28:Linux 2.2.x or 2.4.x
FAF0:05B4:40:00:1:1:1:0:S:LT:Windows 98
FAF0:05B4:40:02:1:1:0:0:A:LT:Windows ME
FAF0:05B4:80:00:1:1:1:1:A:40:Windows XP
FAF0:05B4:80:WS:1:1:1:0:S:30:Windows XP Pro, Windows 2000 Pro
FAF0:05B4:80:WS:1:1:1:0:S:LT:Windows 98 SE / 2000 / XP Professional
FAF0:05B4:FF:WS:0:0:1:0:S:2C:Linux 2.1.xx
FAF0:05B4:FF:WS:1:1:1:0:A:LT:Windows 2000 Pro
FAF0:B405:40:00:0:1:1:0:A:LT:Mac OS X Server 10.1
FAF0:_MSS:80:00:0:1:1:0:A:LT:Windows 2000 Professional, Build 2183 (RC3)
FAF0:_MSS:80:00:0:1:1:1:A:LT:Windows 2000 Professional, Build 2183 (RC3)
FAF0:_MSS:80:WS:0:1:1:0:A:LT:Windows XP Professional Release
FAF0:_MSS:FF:WS:0:0:0:0:A:LT:Solaris 2.6 - 2.7
FE88:B405:40:00:0:1:1:1:A:LT:Mac OS X Server 10.x
FE88:_MSS:FF:WS:0:0:1:0:A:LT:Solaris 2.6 - 2.7
FEFA:_MSS:80:00:0:1:0:0:A:LT:AIX v4.2
FEFA:_MSS:80:00:0:1:0:1:A:LT:AIX v4.2
FFAF:_MSS:80:00:0:0:1:0:A:LT:Solaris 2.3 - 2.4
FFAF:_MSS:80:00:0:1:0:0:A:LT:Hitachi HI-UX/MPP (don't know version)
FFAF:_MSS:80:00:0:1:0:1:A:LT:Hitachi HI-UX/MPP (don't know version)
FFAF:_MSS:80:WS:0:0:0:0:A:LT:AIX 3.2.5 (Bull HardWare)
FFF7:_MSS:80:00:0:1:1:0:A:LT:Solaris 2.6 - 2.7
FFF7:_MSS:80:00:0:1:1:1:A:LT:Solaris 2.6 - 2.7
FFFF:0558:80:WS:0:0:1:0:S:LT:BorderManager 3.5
FFFF:0564:40:WS:0:0:0:0:A:LT:AIX
FFFF:0598:40:WS:0:0:0:0:S:2C:Cisco webcache
FFFF:05AC:40:WS:1:1:1:0:S:LT:Windows 98 Second Edition
FFFF:05AC:80:WS:0:0:1:0:S:LT:Windows 98
FFFF:05B4:40:00:0:1:0:0:S:3C:CacheOS 3.1 on a CacheFlow 6000
FFFF:05B4:40:01:0:1:0:0:S:30:AOL proxy
FFFF:05B4:40:01:0:1:0:1:A:LT:AIX
FFFF:05B4:40:01:0:1:1:1:A:LT:FreeBSD 4.3 - 4.4
FFFF:05B4:40:01:0:1:1:1:S:LT:FreeBSD
FFFF:05B4:40:WS:0:0:0:0:A:LT:Win NT 4.0 SP4
FFFF:05B4:40:WS:0:0:1:0:A:LT:FreeBSD 4.3R
FFFF:05B4:80:WS:1:1:1:0:S:LT:MacOS X
FFFF:05B4:FF:01:0:1:1:0:S:30:Mac OS 9
FFFF:B405:40:00:0:1:1:1:S:LT:FreeBSD
FFFF:B405:40:01:0:1:1:1:S:LT:MacOS X
FFFF:B405:40:02:0:1:1:1:S:LT:Mac OS X 10.x.x
FFFF:B405:FF:02:0:1:0:1:A:LT:AIX
FFFF:_MSS:80:00:0:0:0:0:A:LT:IBM MVS TCP/IP stack V. 3.2 or AIX 4.3.2
FFFF:_MSS:80:00:0:0:1:0:A:LT:MacOS 8.1
FFFF:_MSS:80:00:0:1:0:0:A:LT:AIX 3.2 running on RS/6000
FFFF:_MSS:80:00:0:1:0:1:A:LT:AIX 3.2 running on RS/6000
FFFF:_MSS:80:00:0:1:1:0:A:LT:Cray Unicos 9.0 - 10.0 or Unicos/mk 1.5.1
FFFF:_MSS:80:00:0:1:1:1:A:LT:Cray Unicos 9.0 - 10.0 or Unicos/mk 1.5.1
FFFF:_MSS:80:WS:0:0:0:0:A:LT:IBM MVS TCP/IP stack V. 3.2 or AIX 4.3.2
FFFF:_MSS:80:WS:0:0:1:0:A:LT:Novell NetWare 3.12 - 5.00
FFFF:_MSS:FF:WS:0:0:1:0:A:LT:Solaris 2.6 - 2.7
