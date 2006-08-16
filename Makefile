# Makefile for an IPSec VPN client compatible with Cisco equipment.
# Copyright (C) 2002  Geoffrey Keating
# Copyright (C) 2003-2004  Maurice Massar

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

DESTDIR=
PREFIX=/usr/local
ETCDIR=/etc/vpnc
SBINDIR=$(PREFIX)/sbin
MANDIR=$(PREFIX)/share/man

CC=gcc
CFLAGS=-W -Wall -O3 -Wmissing-declarations -Wwrite-strings -g '-DVERSION="$(shell cat VERSION)"' $(shell libgcrypt-config --cflags)
LDFLAGS=-g $(shell libgcrypt-config --libs)

ifeq ($(shell uname -s), Linux)
SYSDEP=sysdep-linux.o
endif
ifeq ($(shell uname -s), FreeBSD)
CFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN
SYSDEP=sysdep-bsd.o
endif
ifeq ($(shell uname -s), NetBSD)
CFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN
SYSDEP=sysdep-bsd.o
endif
ifeq ($(shell uname -s), DragonFly)
CFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN -DDRAGONFLY_BSD
SYSDEP=sysdep-bsd.o
endif
ifeq ($(shell uname -s), OpenBSD)
CFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN -DNEED_IPLEN_FIX -DNEW_TUN
SYSDEP=sysdep-bsd.o
endif
ifeq ($(shell uname -s), SunOS)
CFLAGS += -DNEED_IPLEN_FIX
LDFLAGS += -lnsl -lresolv -lsocket
SYSDEP=sysdep-svr4.o
endif
ifeq ($(shell uname -s), Darwin)
CFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN -DNEED_IPLEN_FIX -DDARWIN
SYSDEP=sysdep-bsd.o
endif

FILELIST := $(shell echo *.c *.h vpnc-*) Makefile README ChangeLog COPYING TODO VERSION vpnc.conf vpnc.8 pcf2vpnc

vpnc : vpnc.o vpnc-debug.o isakmp-pkt.o tunip.o config.o $(SYSDEP) dh.o math_group.o
	$(CC) -o $@ $^ $(LDFLAGS)

vpnc.o : vpnc-debug.h isakmp.h isakmp-pkt.h dh.h sysdep.h math_group.h config.h VERSION
isakmp-pkt.o : vpnc-debug.h isakmp.h isakmp-pkt.h config.h
tunip.o : vpnc-debug.h sysdep.h vpnc.h config.h
config.o : vpnc-debug.h vpnc.h config.h VERSION
dh.o : dh.h math_group.h
math_group.o : math_group.h
debug.o : vpnc-debug.c vpnc-debug.h

vpnc-debug.c vpnc-debug.h : isakmp.h enum2debug.pl
	./enum2debug.pl isakmp.h >vpnc-debug.c 2>vpnc-debug.h

vpnc.ps : vpnc.c
	enscript -E -G -T 4 --word-wrap -o- $^ | psnup -2 /dev/stdin $@

../vpnc-%.tar.gz : vpnc-$*.tar.gz

etags :
	etags *.[ch]
ctags :
	ctags *.[ch]

vpnc-%.tar.gz : $(FILELIST)
	mkdir vpnc-$*
	cp -al $(FILELIST) vpnc-$*/
	tar zcf ../$@ vpnc-$*
	rm -rf vpnc-$*

dist : VERSION vpnc-$(shell cat VERSION).tar.gz

clean :
	-rm -f vpnc *.o tags

realclean :
	-rm -f vpnc *.o tags vpnc-debug.c vpnc-debug.h

all : vpnc

install :
	install -d $(DESTDIR)$(ETCDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(MANDIR)/man8
	install vpnc.conf vpnc-script $(DESTDIR)$(ETCDIR)
	install vpnc vpnc-disconnect $(DESTDIR)$(SBINDIR)
	install vpnc.8 $(DESTDIR)$(MANDIR)/man8

install-strip :
	install -d $(DESTDIR)$(ETCDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(MANDIR)/man8
	install vpnc.conf vpnc-script $(DESTDIR)$(ETCDIR)
	install -s vpnc $(DESTDIR)$(SBINDIR)
	install vpnc-disconnect $(DESTDIR)$(SBINDIR)
	install vpnc.8 $(DESTDIR)$(MANDIR)/man8

uninstall :
	rm -f $(DESTDIR)$(SBINDIR)/vpnc \
		$(DESTDIR)$(SBINDIR)/vpnc-disconnect \
		$(DESTDIR)$(MANDIR)/man8/vpnc.8
	@echo NOTE: remove $(DESTDIR)$(ETCDIR) manually

.PHONY : clean dist all install install-strip uninstall

#
