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
CFLAGS=-W -Wall -O -g
LDFLAGS=-lgcrypt -g

vpnc : vpnc.o isakmp-pkt.o tunip.o tun_dev-linux.o dh.o math_group.o
	$(CC) -o $@ $^ $(LDFLAGS)

vpnc.o : isakmp.h isakmp-pkt.h dh.h tun_dev.h math_group.h vpnc.h
isakmp-pkt.o : isakmp.h isakmp-pkt.h vpnc.h
tunip.o : tun_dev.h vpnc.h
dh.o : dh.h math_group.h
math_group.o : math_group.h

vpnc-%.tar.gz : vpnc.c vpnc.h isakmp-pkt.c tunip.c isakmp-pkt.h isakmp.h \
  Makefile README COPYING ChangeLog connect disconnect sample-unikl \
  tun_dev.h tun_dev-bsd.c tun_dev-linux.c tun_dev-svr4.c \
  dh.c dh.h math_group.c math_group.h
	mkdir vpnc-$*
	cp -a $^ vpnc-$*/
	tar zcf $@ vpnc-$*
	rm -rf vpnc-$*

clean:
	-rm -f vpnc *.o

.PHONY : clean
#
