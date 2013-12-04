# Makefile to rebuild certificate chain for VPNC test.
# Copyright (C) 2013 Antonio Borneo

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

OPENSSL = openssl

CFG = openssl.cnf
TIME = -days 7120

# default targets empty.
all default clean:

# target to rebuild everything
rebuild: ca_list.pem cert3.pem sig_data.bin

ca1.key cert1.key:
	$(OPENSSL) genrsa -out $@ 4096

ca2.key ca3.key cert0.key cert2.key cert3.key:
	$(OPENSSL) genrsa -out $@ 2048

ca1.pem: ca1.key
ca2.pem: ca2.key
ca3.pem: ca3.key

ca%.pem: ca%.key
	$(OPENSSL) req -new -x509 -key $< -out $@ $(TIME) -batch -text \
		-subj "/OU=Root Certification Authority/CN="$@

ca_list.pem: ca1.pem ca2.pem ca3.pem
	cat $^ > $@

CHAIN_SIGN = $(OPENSSL) req -new -key $(2) -batch -subj "/OU=Cert/CN="$(1) \
	| $(OPENSSL) x509 -req $(TIME) -CA $(3) -CAkey $(4) -set_serial 01 \
		-out $(1) -text -extfile $(CFG) -extensions usr

cert0.pem: cert0.key ca3.pem ca3.key $(CFG)
	$(call CHAIN_SIGN,cert0.pem,cert0.key,ca3.pem,ca3.key)

cert1.pem: cert1.key cert0.pem cert0.key $(CFG)
	$(call CHAIN_SIGN,cert1.pem,cert1.key,cert0.pem,cert0.key)

cert2.pem: cert2.key cert1.pem cert1.key $(CFG)
	$(call CHAIN_SIGN,cert2.pem,cert2.key,cert1.pem,cert1.key)

cert3.pem: cert3.key cert2.pem cert2.key $(CFG)
	$(call CHAIN_SIGN,cert3.pem,cert3.key,cert2.pem,cert2.key)

$(CFG):
	echo -e '[ usr ]\nbasicConstraints=CA:TRUE' > $(CFG)

dec_data.bin:
	dd if=/dev/urandom of=$@ bs=256 count=1

sig_data.bin: dec_data.bin cert0.key
	$(OPENSSL) rsautl -decrypt -in $< -out $@ -inkey cert0.key -raw

clean_build:
	rm -f *.pem $(CFG) sig_data.bin

clean_key:
	rm -f *.key dec_data.bin

clean_all: clean_build clean_key
