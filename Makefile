# Makefile for an IPSec VPN client compatible with Cisco equipment.
# Copyright (C) 2002  Geoffrey Keating

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

CC=gcc
CFLAGS=-W -Wall -O -g '-DVERSION="$(shell cat VERSION)"' $(shell libgcrypt-config --cflags)
LDFLAGS=-g $(shell libgcrypt-config --libs)

ifeq ($(shell uname -s), Linux)
SYSDEP=sysdep-linux.o
endif
ifeq ($(shell uname -s), NetBSD)
CFLAGS += -DSOCKADDR_IN_SIN_LEN
SYSDEP=sysdep-bsd.o
endif
ifeq ($(shell uname -s), FreeBSD)
CFLAGS += -DSOCKADDR_IN_SIN_LEN
SYSDEP=sysdep-bsd.o
endif
ifeq ($(shell uname -s), SunOS)
SYSDEP=sysdep-svr4.o
endif

vpnc : vpnc.o isakmp-pkt.o tunip.o $(SYSDEP) dh.o math_group.o
	$(CC) -o $@ $^ $(LDFLAGS)

vpnc.o : isakmp.h isakmp-pkt.h dh.h sysdep.h math_group.h vpnc.h VERSION
isakmp-pkt.o : isakmp.h isakmp-pkt.h vpnc.h
tunip.o : sysdep.h vpnc.h
dh.o : dh.h math_group.h
math_group.o : math_group.h

FILELIST := $(shell echo *.c *.h vpnc-*) Makefile README ChangeLog COPYING TODO VERSION vpnc.conf

../vpnc-%.tar.gz : vpnc-$*.tar.gz

vpnc-%.tar.gz : $(FILELIST)
	mkdir vpnc-$*
	cp -al $(FILELIST) vpnc-$*/
	tar zcf ../$@ vpnc-$*
	rm -rf vpnc-$*

release: VERSION vpnc-$(shell cat VERSION).tar.gz

clean:
	-rm -f vpnc *.o

.PHONY : clean
#
