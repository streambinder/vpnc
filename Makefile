# Makefile for an IPSec VPN client compatible with Cisco equipment.
# Copyright (C) 2002  Geoffrey Keating
# Copyright (C) 2003-2004  Maurice Massar
# Copyright (C) 2006-2007 Dan Villiom Podlaski Christiansen

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
BINDIR=$(PREFIX)/bin
SBINDIR=$(PREFIX)/sbin
MANDIR=$(PREFIX)/share/man
DOCDIR=$(PREFIX)/share/doc/vpnc

# The license of vpnc (Gpl >= 2) is quite likely incompatible with the
# openssl license. Openssl is one possible library used to provide certificate
# support for vpnc (hybrid only).
# While it is OK for users to build their own binaries linking in openssl
# with vpnc and even providing dynamically linked binaries it is probably
# not OK to provide the binaries inside a distribution.
# See http://www.gnome.org/~markmc/openssl-and-the-gpl.html for further
# details.
# Some distributions like Suse and Fedora seem to think otherwise.

# Comment this in to obtain a binary with certificate support which is
# GPL incompliant though.
#OPENSSL_GPL_VIOLATION=yes

CRYPTO_LDADD = $(shell pkg-config --libs gnutls)
CRYPTO_CFLAGS = $(shell pkg-config --cflags gnutls) -DCRYPTO_GNUTLS
CRYPTO_SRCS = crypto-gnutls.c

ifeq ($(OPENSSL_GPL_VIOLATION), yes)
CRYPTO_LDADD = -lcrypto
CRYPTO_CFLAGS = -DOPENSSL_GPL_VIOLATION -DCRYPTO_OPENSSL
CRYPTO_SRCS = crypto-openssl.c
endif

SRCS = sysdep.c vpnc-debug.c isakmp-pkt.c tunip.c config.c dh.c math_group.c supp.c decrypt-utils.c crypto.c $(CRYPTO_SRCS)
BINS = vpnc cisco-decrypt test-crypto
OBJS = $(addsuffix .o,$(basename $(SRCS)))
CRYPTO_OBJS = $(addsuffix .o,$(basename $(CRYPTO_SRCS)))
BINOBJS = $(addsuffix .o,$(BINS))
BINSRCS = $(addsuffix .c,$(BINS))
VERSION := $(shell sh mk-version)
RELEASE_VERSION := $(shell cat VERSION)

CC=gcc
CFLAGS ?= -O3 -g
CFLAGS += -W -Wall -Wmissing-declarations -Wwrite-strings
CFLAGS +=  $(shell libgcrypt-config --cflags) $(CRYPTO_CFLAGS)
CPPFLAGS += -DVERSION=\"$(VERSION)\"
LDFLAGS ?= -g
LDFLAGS += $(shell libgcrypt-config --libs) $(CRYPTO_LDADD)

ifeq ($(shell uname -s), SunOS)
LDFLAGS += -lnsl -lresolv -lsocket
endif
ifneq (,$(findstring Apple,$(shell $(CC) --version)))
# enabled in FSF GCC, disabled by default in Apple GCC
CFLAGS += -fstrict-aliasing -freorder-blocks -fsched-interblock
endif

all : $(BINS) vpnc.8 vpnc-script

vpnc : $(OBJS) vpnc.o
	$(CC) -o $@ $^ $(LDFLAGS)

vpnc.8 : vpnc.8.template makeman.pl vpnc
	./makeman.pl

vpnc-script : vpnc-script.in
	sed -e 's,@''PREFIX''@,$(PREFIX),g' $< > $@ && chmod 755 $@

cisco-decrypt : cisco-decrypt.o decrypt-utils.o
	$(CC) -o $@ $^ $(LDFLAGS)

test-crypto : test-crypto.o crypto.o $(CRYPTO_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.depend: $(SRCS) $(BINSRCS)
	$(CC) -MM $(SRCS) $(BINSRCS) $(CFLAGS) $(CPPFLAGS) > $@

vpnc-debug.c vpnc-debug.h : isakmp.h enum2debug.pl
	LC_ALL=C perl -w ./enum2debug.pl isakmp.h >vpnc-debug.c 2>vpnc-debug.h

vpnc.ps : vpnc.c
	enscript -E -G -T 4 --word-wrap -o- $^ | psnup -2 /dev/stdin $@

../vpnc-%.tar.gz : vpnc-$*.tar.gz

etags :
	etags *.[ch]
ctags :
	ctags *.[ch]

vpnc-%.tar.gz :
	mkdir vpnc-$*
	LC_ALL=C svn info -R | awk -v RS='' -v FS='\n' '/Node Kind: file/ {print substr($$1,7)}' | \
		tar -cf - -T - | tar -xf - -C vpnc-$*/
	tar -czf ../$@ vpnc-$*
	rm -rf vpnc-$*

test : all
	./test-crypto test/cert.pem test/cert0.pem test/cert1.pem test/cert2.pem test/root.pem
	#./test-crypto test/cert.pem test/cert0.crt test/cert1.crt test/cert2.crt test/root.crt

dist : VERSION vpnc.8 vpnc-$(RELEASE_VERSION).tar.gz

clean :
	-rm -f $(OBJS) $(BINOBJS) $(BINS) tags

distclean : clean
	-rm -f vpnc-debug.c vpnc-debug.h vpnc.ps vpnc.8 .depend vpnc-script

install-common: all
	install -d $(DESTDIR)$(ETCDIR) $(DESTDIR)$(BINDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(MANDIR)/man1 $(DESTDIR)$(MANDIR)/man8 $(DESTDIR)$(DOCDIR)
	if [ "`uname -s | cut -c-6`" = "CYGWIN" ]; then \
		install vpnc-script-win $(DESTDIR)$(ETCDIR)/vpnc-script; \
		install vpnc-script-win.js $(DESTDIR)$(ETCDIR); \
	else \
		install vpnc-script $(DESTDIR)$(ETCDIR); \
	fi
	install -m600 vpnc.conf $(DESTDIR)$(ETCDIR)/default.conf
	install -m755 vpnc-disconnect $(DESTDIR)$(SBINDIR)
	install -m755 pcf2vpnc $(DESTDIR)$(BINDIR)
	install -m644 vpnc.8 $(DESTDIR)$(MANDIR)/man8
	install -m644 pcf2vpnc.1 $(DESTDIR)$(MANDIR)/man1
	install -m644 cisco-decrypt.1 $(DESTDIR)$(MANDIR)/man1
	install -m644 COPYING $(DESTDIR)$(DOCDIR)

install : install-common
	install -m755 vpnc $(DESTDIR)$(SBINDIR)
	install -m755 cisco-decrypt $(DESTDIR)$(BINDIR)

install-strip : install-common
	install -s -m755 vpnc $(DESTDIR)$(SBINDIR)
	install -s -m755 cisco-decrypt $(DESTDIR)$(BINDIR)

uninstall :
	rm -f $(DESTDIR)$(SBINDIR)/vpnc \
		$(DESTDIR)$(SBINDIR)/vpnc-disconnect \
		$(DESTDIR)$(BINDIR)/pcf2vpnc \
		$(DESTDIR)$(BINDIR)/cisco-decrypt \
		$(DESTDIR)$(MANDIR)/man1/cisco-decrypt.1 \
		$(DESTDIR)$(MANDIR)/man1/pcf2vpnc \
		$(DESTDIR)$(MANDIR)/man8/vpnc.8
	@echo NOTE: remove $(DESTDIR)$(ETCDIR) manually

.PHONY : clean distclean dist all install install-strip uninstall

#
-include .depend
