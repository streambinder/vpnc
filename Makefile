# Makefile for an IPSec VPN client compatible with Cisco equipment.
# Copyright (C) 2002  Geoffrey Keating
# Copyright (C) 2003-2004  Maurice Massar
# Copyright (C) 2006 Dan Villiom Podlaski Christiansen

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

SRCS = vpnc.c vpnc-debug.c isakmp-pkt.c tunip.c config.c dh.c math_group.c
OBJS = $(addsuffix .o,$(basename $(SRCS)))

CC=gcc
CFLAGS += -W -Wall -O3 -Wmissing-declarations -Wwrite-strings -g
CPPFLAGS = -DVERSION=\"$(shell cat VERSION)\"
LDFLAGS = -g $(shell libgcrypt-config --libs)
CFLAGS +=  $(shell libgcrypt-config --cflags)

ifeq ($(shell uname -s), Linux)
SRCS +=sysdep-linux.c
endif
ifeq ($(shell uname -s), FreeBSD)
CPPFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN
SRCS +=sysdep-bsd.c
endif
ifeq ($(shell uname -s), NetBSD)
CPPFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN
SRCS +=sysdep-bsd.c
endif
ifeq ($(shell uname -s), DragonFly)
CPPFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN -DDRAGONFLY_BSD
SRCS +=sysdep-bsd.c
endif
ifeq ($(shell uname -s), OpenBSD)
CPPFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN -DNEED_IPLEN_FIX -DNEW_TUN
SRCS +=sysdep-bsd.c
endif
ifeq ($(shell uname -s), SunOS)
CPPFLAGS += -DNEED_IPLEN_FIX
LDFLAGS += -lnsl -lresolv -lsocket
SRCS +=sysdep-svr4.c
endif
ifeq ($(shell uname -s), Darwin)
CPPFLAGS += -DSOCKADDR_IN_SIN_LEN -DHAVE_SA_LEN -DNEED_IPLEN_FIX -DDARWIN
SRCS +=sysdep-bsd.c
endif

FILELIST := $(shell echo *.c *.h vpnc-*) Makefile README ChangeLog COPYING TODO VERSION vpnc.conf vpnc.8 pcf2vpnc

vpnc : $(OBJS)
	@echo $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.depend: $(SRCS)
	$(CC) -MM $(SRCS) $(CFLAGS) $(CPPFLAGS) > $@

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
	-rm -f vpnc tags $(OBJS)

realclean :
	-rm -f vpnc $(OBJS) tags vpnc-debug.c vpnc-debug.h

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
-include .depend
