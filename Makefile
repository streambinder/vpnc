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
#
# $Id$

DESTDIR=
PREFIX=/usr/local
ETCDIR=/etc/vpnc
SBINDIR=$(PREFIX)/sbin
MANDIR=$(PREFIX)/share/man

SRCS = sysdep.c vpnc-debug.c isakmp-pkt.c tunip.c config.c dh.c math_group.c supp.c
BINS = vpnc cisco-decrypt
OBJS = $(addsuffix .o,$(basename $(SRCS)))
BINOBJS = $(addsuffix .o,$(BINS))
BINSRCS = $(addsuffix .c,$(BINS))
VERSION := $(shell sh mk-version)
RELEASE_VERSION := $(shell cat VERSION)

CC=gcc
CFLAGS += -W -Wall -O3 -Wmissing-declarations -Wwrite-strings -g
CPPFLAGS = -DVERSION=\"$(VERSION)\"
LDFLAGS = -g $(shell libgcrypt-config --libs)
CFLAGS +=  $(shell libgcrypt-config --cflags)

ifeq ($(shell uname -s), SunOS)
LDFLAGS += -lnsl -lresolv -lsocket
endif

all : $(BINS)

vpnc : $(OBJS) vpnc.o
	$(CC) -o $@ $^ $(LDFLAGS)

cisco-decrypt : cisco-decrypt.o config.o supp.o sysdep.o vpnc-debug.o
	$(CC) -o $@ $^ $(LDFLAGS)

.depend: $(SRCS) $(BINSRCS)
	$(CC) -MM $(SRCS) $(BINSRCS) $(CFLAGS) $(CPPFLAGS) > $@

vpnc-debug.c vpnc-debug.h : isakmp.h enum2debug.pl
	./enum2debug.pl isakmp.h >vpnc-debug.c 2>vpnc-debug.h

vpnc.ps : vpnc.c
	enscript -E -G -T 4 --word-wrap -o- $^ | psnup -2 /dev/stdin $@

../vpnc-%.tgz : vpnc-$*.tgz

etags :
	etags *.[ch]
ctags :
	ctags *.[ch]

vpnc-%.tgz :
	mkdir vpnc-$*
	svn info -R | awk -v RS='\n\n' -v FS='\n' '/Node Kind: file/ {print substr($$1,7)}' | \
		tar cT - | tar xC vpnc-$*/
	tar zcf ../$@ vpnc-$*
	rm -rf vpnc-$*

dist : VERSION vpnc-$(RELEASE_VERSION).tgz

clean :
	-rm -f $(OBJS) $(BINOBJS) $(BINS) tags

distclean : clean
	-rm -f vpnc-debug.c vpnc-debug.h vpnc.ps .depend

install : all
	install -d $(DESTDIR)$(ETCDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(MANDIR)/man8
	install vpnc-script $(DESTDIR)$(ETCDIR)
	install -m 600 vpnc.conf $(DESTDIR)$(ETCDIR)/default.conf
	install vpnc vpnc-disconnect $(DESTDIR)$(SBINDIR)
	install vpnc.8 $(DESTDIR)$(MANDIR)/man8

install-strip : all
	install -d $(DESTDIR)$(ETCDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(MANDIR)/man8
	install vpnc-script $(DESTDIR)$(ETCDIR)
	install -m 600 vpnc.conf $(DESTDIR)$(ETCDIR)/default.conf
	install -s vpnc $(DESTDIR)$(SBINDIR)
	install vpnc-disconnect $(DESTDIR)$(SBINDIR)
	install vpnc.8 $(DESTDIR)$(MANDIR)/man8

uninstall :
	rm -f $(DESTDIR)$(SBINDIR)/vpnc \
		$(DESTDIR)$(SBINDIR)/vpnc-disconnect \
		$(DESTDIR)$(MANDIR)/man8/vpnc.8
	@echo NOTE: remove $(DESTDIR)$(ETCDIR) manually

.PHONY : clean distclean dist all install install-strip uninstall

#
-include .depend
