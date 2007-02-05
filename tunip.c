/* IPSec ESP and AH support.
   Copyright (c) 1999      Pierre Beyssac
   Copyright (C) 2002      Geoffrey Keating
   Copyright (C) 2003-2007 Maurice Massar
   Copyright (C) 2004      Tomas Mraz
   Copyright (C) 2005      Michael Tilstra
   Copyright (C) 2006      Daniel Roethlisberger
   Copyright (C) 2007      Paolo Zarpellon (tap support)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   $Id$
*/

/* borrowed from pipsecd (-; */

/*-
 * Copyright (c) 1999 Pierre Beyssac
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/select.h>
#include <signal.h>

#ifndef __sun__
#include <err.h>
#endif

#include <gcrypt.h>
#include "sysdep.h"
#include "config.h"
#include "vpnc.h"

#include "tunip.h"

#ifndef MAX
#define MAX(a,b)	((a)>(b)?(a):(b))
#endif

#ifndef FD_COPY
#define FD_COPY(f, t)	((void)memcpy((t), (f), sizeof(*(f))))
#endif

struct sa_desc {
	struct sa_desc *next;

	struct sockaddr_in init; /* initial and fallback remote address */
	struct sockaddr_in dest; /* current remote address */
	struct sockaddr_in source; /* local socket address we send packets from */
	unsigned char use_fallback; /* use initial address as fallback? */
	unsigned char use_dest; /* is dest address known yet? */

	uint32_t spi; /* security parameters index */
	uint32_t seq_id; /* for replay protection (not implemented) */

	/* Encryption key */
	const unsigned char *enc_secret;
	size_t enc_secret_size;
	size_t ivlen;
	/* Preprocessed encryption key */
	gcry_cipher_hd_t cry_ctx;
	int cry_algo;
	size_t blksize;

	/* Authentication secret */
	const unsigned char *auth_secret;
	unsigned int auth_secret_size;
	/* Authentication method to use, or NULL */
	int md_algo;

	/* Encapsulation method to use to send packets */
	struct encap_method *em;

	/* timeout counters */
	time_t last_packet_sent, last_packet_recv, last_checkifaddr;
};

struct peer_desc {
	struct sa_desc *local_sa, *remote_sa;
	int tun_fd; /* file descriptor for associated tunnel device */
	uint8_t *tun_hwaddr;
};

/* A real ESP header (RFC 2406) */
typedef struct esp_encap_header {
	uint32_t spi; /* security parameters index */
	uint32_t seq_id; /* sequence id (unimplemented) */
	/* variable-length payload data + padding */
	/* unsigned char next_header */
	/* optional auth data */
} esp_encap_header_t;

struct encap_method {
	int fd; /* file descriptor for relevant socket */
	const char *name;

	int fixed_header_size;

	/* Description of the packet being processed */
	unsigned char *buf;
	unsigned int bufsize, bufpayload, var_header_size;
	int buflen;
	struct sockaddr_in from;
	socklen_t fromlen;

	int (*recv) (struct encap_method * encap,
		unsigned char *buf, unsigned int bufsize, struct sockaddr_in * from);
	struct peer_desc *(*peer_find) (struct encap_method * encap);
	void (*send_peer) (struct encap_method * encap,
		struct peer_desc * peer, unsigned char *buf, unsigned int bufsize);
	int (*recv_peer) (struct encap_method * encap, struct peer_desc * peer);
};

/* Forward decl */
void encap_esp_send_peer(struct encap_method *encap,
	struct peer_desc *peer, unsigned char *buf, unsigned int bufsize);
void encap_udp_send_peer(struct encap_method *encap,
	struct peer_desc *peer, unsigned char *buf, unsigned int bufsize);
struct peer_desc *peer_find(uint32_t spi, struct encap_method *encap);
int encap_esp_recv_peer(struct encap_method *encap, struct peer_desc *peer);

/* Yuck! Global variables... */

extern int natt_draft;

#define MAX_HEADER 72
#define MAX_PACKET 4096
uint8_t buf[MAX_HEADER + MAX_PACKET + ETH_HLEN];

struct peer_desc vpnpeer;

unsigned short ip_id;

struct sa_block oursa[1];

/* Security associations lists */
struct sa_desc *local_sa_list = NULL;
struct sa_desc *remote_sa_list = NULL;

#define encap_get_fd(e)	((e)->fd)
#define encap_recv(e,b,bs,f) \
	((e)->recv((e),(b),(bs),(f)))
#define encap_peer_find(e) \
	((e)->peer_find((e)))
#define encap_send_peer(e,p,b,bs) \
	((e)->send_peer((e),(p),(b),(bs)))
#define encap_recv_peer(e,p) \
	((e)->recv_peer((e),(p)))

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
static u_short in_cksum(addr, len)
	u_short *addr;
	int len;
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return (answer);
}

/*
 * Decapsulate from a raw IP packet
 */
static int encap_rawip_recv(struct encap_method *encap,
	unsigned char *buf, unsigned int bufsize, struct sockaddr_in *from)
{
	ssize_t r;
	struct ip *p = (struct ip *)buf;

	encap->fromlen = sizeof(encap->from);

	r = recvfrom(encap->fd, buf, bufsize, 0, (struct sockaddr *)&encap->from, &encap->fromlen);
	if (r == -1) {
		syslog(LOG_ERR, "recvfrom: %m");
		return -1;
	}
	if (r < (p->ip_hl << 2) + encap->fixed_header_size) {
		syslog(LOG_ALERT, "packet too short from %s", inet_ntoa(encap->from.sin_addr));
		return -1;
	}
#if 0
	printf("raw got %d bytes\n", r);
	for (i = 0; i < r; i++) {
		printf(" %02x", buf[i]);
		if ((i & 15) == 15)
			printf("\n");
	}
	printf("\n");
#endif

#ifdef NEED_IPID_SWAP
	p->ip_id = htons(p->ip_id);
#endif
#ifdef NEED_IPLEN_FIX
	p->ip_len = r;
#else
	p->ip_len = ntohs(r);
#endif

	encap->buf = buf;
	encap->buflen = r;
	encap->bufpayload = (p->ip_hl << 2);
	encap->bufsize = bufsize;
	*from = encap->from;
	return r;
}

/*
 * Decapsulate from an UDP packet
 */
static int encap_udp_recv(struct encap_method *encap,
	unsigned char *buf, unsigned int bufsize,
	struct sockaddr_in *from)
{
	ssize_t r;

	encap->fromlen = sizeof(encap->from);

	r = recvfrom(encap->fd, buf, bufsize, 0,
		(struct sockaddr *)&encap->from, &encap->fromlen);
	if (r == -1) {
		syslog(LOG_ERR, "recvfrom: %m");
		return -1;
	}
	if (natt_draft < 2 && r > 8) {
		r -= 8;
		memmove(buf, buf + 8, r);
	}
	if (r < encap->fixed_header_size) {
		syslog(LOG_ALERT, "packet too short from %s",
			inet_ntoa(encap->from.sin_addr));
		return -1;
	}

#if 0
	printf("udp got %d bytes\n", r);
	for (i = 0; i < r; i++) {
		printf(" %02x", buf[i]);
		if ((i & 15) == 15) printf("\n");
	}
	printf("\n");
#endif

	encap->buf = buf;
	encap->buflen = r;
	encap->bufpayload = 0;
	encap->bufsize = bufsize;
	*from = encap->from;
	return r;
}

static struct peer_desc *encap_esp_peer_find(struct encap_method *encap)
{
	esp_encap_header_t *eh;
	eh = (esp_encap_header_t *) (encap->buf + encap->bufpayload);
	return peer_find(ntohl(eh->spi), encap);
}

/*
 * Decapsulate packet
 */
static int encap_any_decap(struct encap_method *encap)
{
	encap->buflen -= encap->bufpayload + encap->fixed_header_size + encap->var_header_size;
	encap->buf += encap->bufpayload + encap->fixed_header_size + encap->var_header_size;
	if (encap->buflen == 0)
		return 0;
	return 1;
}

/*
 * Send decapsulated packet to tunnel device
 */
static int tun_send_ip(struct encap_method *encap, int fd, uint8_t *hwaddr)
{
	int sent, len;
	uint8_t *start;
	
	start = encap->buf;
	len = encap->buflen;
	
	if (opt_if_mode == IF_MODE_TAP) {
		/*
		 * Add ethernet header before encap->buf where
		 * at least ETH_HLEN bytes should be available.
		 */
		struct ether_header *eth_hdr = (struct ether_header *) (encap->buf - ETH_HLEN);
		
		memcpy(eth_hdr->ether_dhost, hwaddr, ETH_ALEN);
		memcpy(eth_hdr->ether_shost, hwaddr, ETH_ALEN);
		
		/* Use a different MAC as source */
		eth_hdr->ether_shost[0] ^= 0x80; /* toggle some visible bit */
		eth_hdr->ether_type = htons(ETHERTYPE_IP);
		
		start = (uint8_t *) eth_hdr;
		len += ETH_HLEN;
	}
	
	sent = tun_write(fd, start, len);
	if (sent != len)
		syslog(LOG_ERR, "truncated in: %d -> %d\n", len, sent);
	hex_dump("Tx pkt", start, len);
	return 1;
}

static int encap_esp_new(struct encap_method *encap, unsigned char proto)
{
#ifdef IP_HDRINCL
	int hincl = 1;
#endif

	encap->fd = socket(PF_INET, SOCK_RAW, proto);

	if (encap->fd == -1) {
		perror("socket(SOCK_RAW)");
		return -1;
	}
#ifdef IP_HDRINCL
	if (setsockopt(encap->fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl))
		== -1) {
		perror("setsockopt(IP_HDRINCL)");
		close(encap->fd);
		return -1;
	}
#endif
	encap->name = "ipesp";
	encap->recv = encap_rawip_recv;
	encap->peer_find = encap_esp_peer_find;
	encap->send_peer = encap_esp_send_peer;
	encap->recv_peer = encap_esp_recv_peer;
	encap->fixed_header_size = sizeof(esp_encap_header_t);
	encap->var_header_size = 0;
	return 0;
}

static int encap_udp_new(struct encap_method *encap, int udp_fd)
{
	encap->fd = udp_fd;

	encap->name = "udpesp";
	encap->recv = encap_udp_recv;
	encap->peer_find = encap_esp_peer_find;
	encap->send_peer = encap_udp_send_peer;
	encap->recv_peer = encap_esp_recv_peer;
	encap->fixed_header_size = sizeof(esp_encap_header_t);
	encap->var_header_size = 0;
	return 0;
}

/*
 * This is a hack to retrieve which local IP address the system would use
 * as a source when sending packets to a given destination.
 */
int find_local_addr(struct sockaddr_in *dest, struct sockaddr_in *source)
{
	socklen_t addrlen;
	struct sockaddr_in dest_socket;
	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		syslog(LOG_ERR, "socket: %m");
		return -1;
	}

	memset(&dest_socket, 0, sizeof(dest_socket));

	dest_socket.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	dest_socket.sin_len = sizeof(dest_socket);
#endif
	dest_socket.sin_addr = dest->sin_addr;
	dest_socket.sin_port = htons(4444);

	if (connect(fd, (struct sockaddr *)&dest_socket, sizeof(dest_socket)) == -1) {
		syslog(LOG_ERR, "connect: %m");
		close(fd);
		return -1;
	}

	addrlen = sizeof(*source);

	if (getsockname(fd, (struct sockaddr *)source, &addrlen) == -1) {
		syslog(LOG_ERR, "getsockname: %m");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/*
 * Retrieve and possibly update our local address to a given remote SA.
 * Return 1 if changed, 0 if not, -1 if error.
 */
static int update_sa_addr(struct sa_desc *p)
{
	struct sockaddr_in new_addr;

	if (find_local_addr(&p->dest, &new_addr) == -1) {
		syslog(LOG_ALERT,
			"can't find a local address for packets to %s",
			inet_ntoa(p->dest.sin_addr));
		return -1;
	}
	if (new_addr.sin_addr.s_addr != p->source.sin_addr.s_addr) {
		char addr1[16];
		p->source.sin_addr = new_addr.sin_addr;
		strcpy(addr1, inet_ntoa(p->dest.sin_addr));
		syslog(LOG_NOTICE,
			"local address for %s is %s", addr1, inet_ntoa(p->source.sin_addr));
		return 1;
	}
	return 0;
}

/*
 * Find the peer record associated with a given local SPI.
 */
struct peer_desc *peer_find(uint32_t spi, struct encap_method *encap)
{
	if (vpnpeer.local_sa->spi == spi && vpnpeer.local_sa->em == encap)
		return &vpnpeer;
	syslog(LOG_ALERT, "unknown spi %u", spi);
	return NULL;
}

/*
 * Compute HMAC for an arbitrary stream of bytes
 */
static int hmac_compute(int md_algo,
	const unsigned char *data, unsigned int data_size,
	unsigned char *digest, unsigned char do_store,
	const unsigned char *secret, unsigned short secret_size)
{
	gcry_md_hd_t md_ctx;
	int ret;
	unsigned char *hmac_digest;
	unsigned int hmac_len;

	/* See RFC 2104 */
	gcry_md_open(&md_ctx, md_algo, GCRY_MD_FLAG_HMAC);
	assert(md_ctx != 0);
	ret = gcry_md_setkey(md_ctx, secret, secret_size);
	assert(ret == 0);
	gcry_md_write(md_ctx, data, data_size);
	gcry_md_final(md_ctx);
	hmac_digest = gcry_md_read(md_ctx, 0);
	hmac_len = 12; /*gcry_md_get_algo_dlen(md_algo); see RFC .. only use 96 bit */

	if (do_store) {
		memcpy(digest, hmac_digest, hmac_len);
		ret = 0;
	} else
		ret = memcmp(digest, hmac_digest, hmac_len);

	gcry_md_close(md_ctx);
	return ret;
}

/*
 * Encapsulate a packet in ESP
 */
static void encap_esp_encapsulate(struct encap_method *encap,
	struct peer_desc *peer)
{
	esp_encap_header_t *eh;
	unsigned char *iv, *cleartext;
	size_t i, padding, pad_blksz;
	unsigned int cleartextlen;

	/*
	 * Add padding as necessary
	 *
	 * done: this should be checked, RFC 2406 section 2.4 is quite
	 *      obscure on that point.
	 * seems fine
	 */
	pad_blksz = peer->remote_sa->blksize;
	while (pad_blksz & 3) /* must be multiple of 4 */
		pad_blksz <<= 1;
	padding = pad_blksz - ((encap->buflen + 2 - encap->var_header_size - encap->bufpayload) % pad_blksz);
	DEBUG(2, printf("sending packet: len = %d, padding = %lu\n", encap->buflen, (unsigned long)padding));
	if (padding == pad_blksz)
		padding = 0;

	for (i = 1; i <= padding; i++) {
		encap->buf[encap->buflen] = i;
		encap->buflen++;
	}

	/* Add trailing padlen and next_header */
	encap->buf[encap->buflen++] = padding;
	encap->buf[encap->buflen++] = IPPROTO_IPIP;

	cleartext = encap->buf + encap->var_header_size + encap->bufpayload;
	cleartextlen = encap->buflen - encap->var_header_size - encap->bufpayload;

	eh = (esp_encap_header_t *) (encap->buf + encap->bufpayload);
	eh->spi = htonl(peer->remote_sa->spi);
	eh->seq_id = htonl(++peer->remote_sa->seq_id);

	/* Copy initialization vector in packet */
	iv = (unsigned char *)(eh + 1);
	gcry_create_nonce(iv, peer->remote_sa->ivlen);
	hex_dump("iv", iv, peer->remote_sa->ivlen);
	hex_dump("auth_secret", peer->remote_sa->auth_secret, peer->remote_sa->auth_secret_size);

#if 1
	hex_dump("sending ESP packet (before crypt)", encap->buf, encap->buflen);
#endif

	if (peer->remote_sa->cry_algo) {
		gcry_cipher_setiv(peer->remote_sa->cry_ctx, iv, peer->remote_sa->ivlen);
		gcry_cipher_encrypt(peer->remote_sa->cry_ctx, cleartext, cleartextlen, NULL, 0);
	}

#if 1
	hex_dump("sending ESP packet (after crypt)", encap->buf, encap->buflen);
#endif

	/* Handle optional authentication field */
	if (peer->remote_sa->md_algo) {
		hmac_compute(peer->remote_sa->md_algo,
			encap->buf + encap->bufpayload,
			encap->var_header_size + cleartextlen,
			encap->buf + encap->bufpayload
			+ encap->var_header_size + cleartextlen,
			1, peer->remote_sa->auth_secret, peer->remote_sa->auth_secret_size);
		encap->buflen += 12; /*gcry_md_get_algo_dlen(md_algo); see RFC .. only use 96 bit */
#if 1
		hex_dump("sending ESP packet (after ah)", encap->buf, encap->buflen);
#endif
	}
}

/*
 * Encapsulate a packet in IP ESP and send to the peer.
 * "buf" should have exactly MAX_HEADER free bytes at its beginning
 * to account for encapsulation data (not counted in "size").
 */
void encap_esp_send_peer(struct encap_method *encap,
	struct peer_desc *peer,
	unsigned char *buf, unsigned int bufsize)
{
	ssize_t sent;
	struct ip *tip, *ip;

	buf += MAX_HEADER;

	/* Keep a pointer to the old IP header */
	tip = (struct ip *)buf;

	encap->buf = buf;
	encap->buflen = bufsize;

	/* Prepend our encapsulation header and new IP header */
	encap->var_header_size = (encap->fixed_header_size + peer->remote_sa->ivlen);

	encap->buf -= sizeof(struct ip) + encap->var_header_size;
	encap->buflen += sizeof(struct ip) + encap->var_header_size;

	encap->bufpayload = sizeof(struct ip);

	ip = (struct ip *)(encap->buf);
	/* Fill non-mutable fields */
	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;
	/*gcry_md_get_algo_dlen(md_algo); see RFC .. only use 96 bit */
	ip->ip_id = htons(ip_id++);
	ip->ip_p = IPPROTO_ESP;
	ip->ip_src = peer->remote_sa->source.sin_addr;
	ip->ip_dst = peer->remote_sa->dest.sin_addr;

	/* Fill mutable fields */
	ip->ip_tos = (bufsize < sizeof(struct ip)) ? 0 : tip->ip_tos;
	ip->ip_off = 0;
	ip->ip_ttl = IPDEFTTL;
	ip->ip_sum = 0;

	encap_esp_encapsulate(encap, peer);

	ip->ip_len = encap->buflen;
#ifdef NEED_IPLEN_FIX
	ip->ip_len = htons(ip->ip_len);
#endif
	ip->ip_sum = in_cksum((u_short *) encap->buf, sizeof(struct ip));

	sent = sendto(encap->fd, encap->buf, encap->buflen, 0,
		(struct sockaddr *)&peer->remote_sa->dest, sizeof(peer->remote_sa->dest));
	if (sent == -1) {
		syslog(LOG_ERR, "sendto: %m");
		return;
	}
	if (sent != encap->buflen)
		syslog(LOG_ALERT, "truncated out (%lld out of %d)", (long long)sent, encap->buflen);
}

/*
 * Encapsulate a packet in UDP ESP and send to the peer.
 * "buf" should have exactly MAX_HEADER free bytes at its beginning
 * to account for encapsulation data (not counted in "size").
 */
void encap_udp_send_peer(struct encap_method *encap,
	struct peer_desc *peer,
	unsigned char *buf, unsigned int bufsize)
{
	ssize_t sent;
	
	buf += MAX_HEADER;
	
	encap->buf = buf;
	encap->buflen = bufsize;
	
	/* Prepend our encapsulation header and new IP header */
	encap->var_header_size = (encap->fixed_header_size + peer->remote_sa->ivlen);
	
	encap->buf -= encap->var_header_size;
	encap->buflen += encap->var_header_size;
	
	encap->bufpayload = 0;
	
	encap_esp_encapsulate(encap, peer);
	
	if (natt_draft < 2) {
		encap->buf -= 8;
		encap->buflen += 8;
		memset(encap->buf, 0, 8);
	}
	
	sent = sendto(encap->fd, encap->buf, encap->buflen, 0,
		(struct sockaddr *)&peer->remote_sa->dest, sizeof(peer->remote_sa->dest));
	if (sent == -1) {
		syslog(LOG_ERR, "sendto: %m");
		return;
	}
	if (sent != encap->buflen)
		syslog(LOG_ALERT, "truncated out (%lld out of %d)",
			(long long)sent, encap->buflen);
}

int encap_esp_recv_peer(struct encap_method *encap, struct peer_desc *peer)
{
	int len, i;
	size_t blksz;
	unsigned char padlen, next_header;
	unsigned char *pad;
	unsigned char *iv;
	struct esp_encap_header *eh;

	eh = (struct esp_encap_header *)(encap->buf + encap->bufpayload);
	encap->var_header_size = peer->local_sa->ivlen;
	iv = encap->buf + encap->bufpayload + encap->fixed_header_size;

	len = encap->buflen - encap->bufpayload - encap->fixed_header_size - encap->var_header_size;

	if (len < 0) {
		syslog(LOG_ALERT, "Packet too short");
		return -1;
	}

	/* Handle optional authentication field */
	if (peer->local_sa->md_algo) {
		len -= 12; /*gcry_md_get_algo_dlen(peer->local_sa->md_algo); */
		encap->buflen -= 12;
		if (hmac_compute(peer->local_sa->md_algo,
				encap->buf + encap->bufpayload,
				encap->fixed_header_size + encap->var_header_size + len,
				encap->buf + encap->bufpayload
				+ encap->fixed_header_size + encap->var_header_size + len,
				0,
				peer->local_sa->auth_secret,
				peer->local_sa->auth_secret_size) != 0) {
			syslog(LOG_ALERT, "HMAC mismatch in ESP mode");
			return -1;
		}
	}

	blksz = peer->local_sa->blksize;
	if ((len % blksz) != 0) {
		syslog(LOG_ALERT,
			"payload len %d not a multiple of algorithm block size %lu", len,
			(unsigned long)blksz);
		return -1;
	}
	
	hex_dump("receiving ESP packet (before decrypt)",
		&encap->buf[encap->bufpayload + encap->fixed_header_size +
			 encap->var_header_size], len);

	if (peer->remote_sa->cry_algo) {
		unsigned char *data;

		data = (encap->buf + encap->bufpayload
			+ encap->fixed_header_size + encap->var_header_size);
		gcry_cipher_setiv(peer->local_sa->cry_ctx, iv, peer->local_sa->ivlen);
		gcry_cipher_decrypt(peer->local_sa->cry_ctx, data, len, NULL, 0);
	}

	hex_dump("receiving ESP packet (after decrypt)",
		&encap->buf[encap->bufpayload + encap->fixed_header_size +
			encap->var_header_size], len);
	
	padlen = encap->buf[encap->bufpayload
		+ encap->fixed_header_size + encap->var_header_size + len - 2];
	next_header = encap->buf[encap->bufpayload
		+ encap->fixed_header_size + encap->var_header_size + len - 1];

	if (padlen + 2 > len) {
		syslog(LOG_ALERT, "Inconsistent padlen");
		return -1;
	}
	if (next_header != IPPROTO_IPIP) {
		syslog(LOG_ALERT, "Inconsistent next_header %d", next_header);
		return -1;
	}
#if 0
	printf("pad len: %d, next_header: %d\n", padlen, next_header);
#endif
	len -= padlen + 2;
	encap->buflen -= padlen + 2;

	/* Check padding */
	pad = encap->buf + encap->bufpayload
		+ encap->fixed_header_size + encap->var_header_size + len;
	for (i = 1; i <= padlen; i++) {
		if (*pad != i) {
			syslog(LOG_ALERT, "Bad padding");
			return -1;
		}
		pad++;
	}

	return 0;
}

/*
 * Process ARP
 * Return 1 if packet has been processed, 0 otherwise
 */
static int process_arp(int fd, uint8_t *hwaddr, uint8_t *frame)
{
	int frame_size;
	uint8_t tmp[4];
	struct ether_header *eth = (struct ether_header *) frame;
	struct ether_arp *arp = (struct ether_arp *) (frame + ETH_HLEN);
	
	if (ntohs(eth->ether_type) != ETHERTYPE_ARP) {
		return 0;
	}
	
	if (ntohs(arp->arp_hrd) != ARPHRD_ETHER ||
		ntohs(arp->arp_pro) != 0x800 ||
		arp->arp_hln != ETH_ALEN ||
		arp->arp_pln != 4 ||
		ntohs(arp->arp_op) != ARPOP_REQUEST ||
		!memcmp(arp->arp_spa, arp->arp_tpa, 4) ||
		memcmp(eth->ether_shost, hwaddr, ETH_ALEN)) {
		/* whatever .. just drop it */
		return 1;
	}
	
	/* send arp reply */
	
	memcpy(eth->ether_dhost, hwaddr, ETH_ALEN);
	eth->ether_shost[0] ^= 0x80; /* Use a different MAC as source */
	
	memcpy(tmp, arp->arp_spa, 4);
	memcpy(arp->arp_spa, arp->arp_tpa, 4);
	memcpy(arp->arp_tpa, tmp, 4);
	
	memcpy(arp->arp_tha, hwaddr, ETH_ALEN);
	arp->arp_sha[0] ^= 0x80; /* Use a different MAC as source */
	
	arp->arp_op = htons(ARPOP_REPLY);
	
	frame_size = ETH_HLEN + sizeof(struct ether_arp);
	tun_write(fd, frame, frame_size);
	hex_dump("ARP reply", frame, frame_size);
	
	return 1;
}

/*
 * Process non-IP packets
 * Return 1 if packet has been processed, 0 otherwise
 */
static int process_non_ip(uint8_t *frame)
{
	struct ether_header *eth = (struct ether_header *) frame;
	
	if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
		/* drop non-ip traffic */
		return 1;
	}
	
	return 0;
}

static void process_tun(struct peer_desc *peer)
{
	int pack;
	int size = MAX_PACKET;
	uint8_t *start = buf + MAX_HEADER;
	
	if (opt_if_mode == IF_MODE_TAP) {
		/* Make sure IP packet starts at buf + MAX_HEADER */
		start -= ETH_HLEN;
		size += ETH_HLEN;
	}
	
	/* Receive a packet from the tunnel interface */
	pack = tun_read(peer->tun_fd, start, size);
	
	hex_dump("Rx pkt", start, pack);
	
	if (opt_if_mode == IF_MODE_TAP) {
		if (process_arp(peer->tun_fd, peer->tun_hwaddr, start)) {
			return;
		}
		if (process_non_ip(start)) {
			return;
		}
		pack -= ETH_HLEN;
	}
	
	if (pack == -1) {
		syslog(LOG_ERR, "read: %m");
		return;
	}
	
	if (peer->remote_sa->use_dest == 0) {
		syslog(LOG_NOTICE, "peer hasn't a known address yet");
		return;
	}
	
	if (((struct ip *)(buf + MAX_HEADER))->ip_dst.s_addr
		== peer->remote_sa->dest.sin_addr.s_addr) {
		syslog(LOG_ALERT, "routing loop to %s",
			inet_ntoa(peer->remote_sa->dest.sin_addr));
		return;
	}
	
	/* Encapsulate and send to the other end of the tunnel */
	encap_send_peer(peer->remote_sa->em, peer, buf, pack);
	
	/* Update sent packet timeout */
	peer->remote_sa->last_packet_sent = time(NULL);
}

static void process_socket(struct encap_method *meth)
{
	/* Receive a packet from a socket */
	struct peer_desc *peer;
	int pack;
	struct sockaddr_in from;
	uint8_t *start = buf;
	
	if (opt_if_mode == IF_MODE_TAP) {
		start += ETH_HLEN;
	}
	
	pack = encap_recv(meth, start, MAX_HEADER + MAX_PACKET, &from);
	if (pack == -1)
		return;
	
	peer = encap_peer_find(meth);
	if (peer == NULL) {
		syslog(LOG_NOTICE, "unknown spi from %s", inet_ntoa(from.sin_addr));
		return;
	}
	
	/* Check auth digest and/or decrypt */
	if (encap_recv_peer(meth, peer) != 0)
		return;
	
	/* Check origin IP; update our copy if need be */
	if (peer->remote_sa->use_dest == 0
		|| from.sin_addr.s_addr != peer->remote_sa->dest.sin_addr.s_addr) {
		/* remote end changed address */
		char addr1[16];
		strcpy(addr1, inet_ntoa(peer->remote_sa->dest.sin_addr));
		syslog(LOG_NOTICE,
			"spi %u: remote address changed from %s to %s",
			peer->remote_sa->spi, addr1, inet_ntoa(from.sin_addr));
		peer->remote_sa->dest.sin_addr.s_addr = from.sin_addr.s_addr;
		peer->remote_sa->use_dest = 1;
		update_sa_addr(peer->remote_sa);
	}
	/* Update received packet timeout */
	peer->remote_sa->last_packet_recv = time(NULL);
	
	if (encap_any_decap(meth) == 0)
		syslog(LOG_DEBUG, "received update probe from peer");
	else
		/* Send the decapsulated packet to the tunnel interface */
		tun_send_ip(meth, peer->tun_fd, peer->tun_hwaddr);
}

static uint8_t volatile do_kill;
static uint8_t *kill_packet;
static size_t kill_packet_size;
static struct sockaddr *kill_dest;

static void vpnc_main_loop(struct peer_desc *peer, struct encap_method *meth, const char *pidfile)
{
	fd_set rfds, refds;
	int nfds=0, encap_fd =-1;
	int enable_keepalives;

	/* non-esp marker, nat keepalive payload (0xFF) */
	char keepalive_v2[5] = { 0x00, 0x00, 0x00, 0x00, 0xFF };
	char keepalive_v1[1] = { 0xFF };
	char *keepalive;
	size_t keepalive_size;
	
	if (natt_draft < 2) {
		keepalive = keepalive_v1;
		keepalive_size = sizeof(keepalive_v1);
	} else {
		keepalive = keepalive_v2;
		keepalive_size = sizeof(keepalive_v2);
	}

	/* send keepalives if UDP encapsulation is enabled */
	enable_keepalives = !strcmp(meth->name, "udpesp");

	FD_ZERO(&rfds);
	FD_SET(peer->tun_fd, &rfds);
	nfds = MAX(nfds, peer->tun_fd +1);

	encap_fd = encap_get_fd (meth);
	FD_SET(encap_fd, &rfds);
	nfds = MAX(nfds, encap_fd +1);

	while (!do_kill) {
		int presult;

		do {
			struct timeval select_timeout = { .tv_sec = 10 };
			struct timeval *tvp = NULL;
			FD_COPY(&rfds, &refds);
			if (enable_keepalives)
				tvp = &select_timeout;
			presult = select(nfds, &refds, NULL, NULL, tvp);
			if (presult == 0 && enable_keepalives) {
				/* send nat keepalive packet */
				if(sendto(meth->fd, keepalive, keepalive_size, 0,
					(struct sockaddr*)&peer->remote_sa->dest,
					sizeof(peer->remote_sa->dest)) == -1) {
					syslog(LOG_ERR, "sendto: %m");
				}
			}
		} while ((presult == 0 || (presult == -1 && errno == EINTR)) && !do_kill);
		if (presult == -1) {
			syslog(LOG_ERR, "select: %m");
			continue;
		}

		if (FD_ISSET(peer->tun_fd, &refds)) {
			process_tun(peer);
		}
		if (FD_ISSET(encap_fd, &refds) ) {
			process_socket(meth);
		}
	}
	
	sendrecv(NULL, 0, kill_packet, kill_packet_size, 1);
	tun_close(oursa->tun_fd, oursa->tun_name);
	if (pidfile)
		unlink(pidfile); /* ignore errors */
	syslog(LOG_NOTICE, "terminated");
}

static void killit(int signum)
{
	do_kill = signum; /* unused */
	do_kill = 1;
}

static void write_pidfile(const char *pidfile)
{
	FILE *pf;

	if (pidfile == NULL || pidfile[0] == '\0')
		return;

	pf = fopen(pidfile, "w");
	if (pf == NULL) {
		syslog(LOG_WARNING, "can't open pidfile %s for writing", pidfile);
		return;
	}

	fprintf(pf, "%d\n", (int)getpid());
	fclose(pf);
}

void
vpnc_doit(unsigned long tous_spi,
	const unsigned char *tous_key,
	struct sockaddr_in *tous_dest,
	unsigned long tothem_spi,
	const unsigned char *tothem_key,
	struct sockaddr_in *tothem_dest,
	int tun_fd, uint8_t *tun_hwaddr,
	int md_algo, int cry_algo,
	uint8_t * kill_packet_p, size_t kill_packet_size_p,
	struct sockaddr *kill_dest_p,
	uint16_t encap_mode, int udp_fd,
	const char *pidfile)
{
	struct encap_method meth;

	static struct sa_desc tous_sa, tothem_sa;
	time_t t = time(NULL);

	switch (encap_mode) {
		case IPSEC_ENCAP_TUNNEL:
			if (encap_esp_new(&meth, IPPROTO_ESP) == -1)
				exit(1);
			break;
		case IPSEC_ENCAP_UDP_TUNNEL:
		case IPSEC_ENCAP_UDP_TUNNEL_OLD:
			if (encap_udp_new(&meth, udp_fd) == -1)
				exit(1);
			break;
		default:
			abort();
	}

	memset(&tous_sa, 0, sizeof(struct sa_desc));
	tous_sa.next = remote_sa_list;
	remote_sa_list = &tous_sa;
	tous_sa.em = &meth;
	tous_sa.last_packet_recv = t;
	tous_sa.last_packet_sent = t;
	tous_sa.last_checkifaddr = t;
	tous_sa.md_algo = md_algo;
	tous_sa.spi = htonl(tous_spi);
	tous_sa.enc_secret = tous_key;
	if (cry_algo)
		gcry_cipher_algo_info(cry_algo, GCRYCTL_GET_KEYLEN, NULL, &(tous_sa.enc_secret_size));
	else
		tous_sa.enc_secret_size = 0;
	hex_dump("tous.enc_secret", tous_sa.enc_secret, tous_sa.enc_secret_size);
	tous_sa.auth_secret = tous_key + tous_sa.enc_secret_size;
	tous_sa.auth_secret_size = gcry_md_get_algo_dlen(md_algo);
	hex_dump("tous.auth_secret", tous_sa.auth_secret, tous_sa.auth_secret_size);
	memcpy(&tous_sa.init, tous_dest, sizeof(struct sockaddr_in));
	memcpy(&tous_sa.dest, tous_dest, sizeof(struct sockaddr_in));
	if (update_sa_addr(&tous_sa) != -1) {
		tous_sa.use_fallback = 1;
		tous_sa.use_dest = 1;
	}
	tous_sa.cry_algo = cry_algo;
	if (cry_algo) {
		gcry_cipher_open(&tous_sa.cry_ctx, tous_sa.cry_algo, GCRY_CIPHER_MODE_CBC, 0);
		gcry_cipher_setkey(tous_sa.cry_ctx, tous_sa.enc_secret, tous_sa.enc_secret_size);
		gcry_cipher_algo_info(tous_sa.cry_algo, GCRYCTL_GET_BLKLEN, NULL, &(tous_sa.ivlen));
	} else {
		tous_sa.cry_ctx = NULL;
		tous_sa.ivlen = 0;
		tous_sa.blksize = 8; /* seems to be this without encryption... */
	}

	memset(&tothem_sa, 0, sizeof(struct sa_desc));
	tothem_sa.next = local_sa_list;
	local_sa_list = &tothem_sa;
	tothem_sa.em = &meth;
	tothem_sa.last_packet_recv = t;
	tothem_sa.last_packet_sent = t;
	tothem_sa.last_checkifaddr = t;
	tothem_sa.md_algo = md_algo;
	tothem_sa.spi = htonl(tothem_spi);
	tothem_sa.enc_secret = tothem_key;
	if (cry_algo)
		gcry_cipher_algo_info(cry_algo, GCRYCTL_GET_KEYLEN, NULL, &(tothem_sa.enc_secret_size));
	else
		tothem_sa.enc_secret_size = 0;
	hex_dump("tothem.enc_secret", tothem_sa.enc_secret, tothem_sa.enc_secret_size);
	tothem_sa.auth_secret = tothem_key + tothem_sa.enc_secret_size;
	tothem_sa.auth_secret_size = gcry_md_get_algo_dlen(md_algo);
	hex_dump("tothem.auth_secret", tothem_sa.auth_secret, tothem_sa.auth_secret_size);
	memcpy(&tothem_sa.init, tothem_dest, sizeof(struct sockaddr_in));
	memcpy(&tothem_sa.dest, tothem_dest, sizeof(struct sockaddr_in));
	if (update_sa_addr(&tothem_sa) != -1) {
		tothem_sa.use_fallback = 1;
		tothem_sa.use_dest = 1;
	}
	tothem_sa.cry_algo = cry_algo;
	if (cry_algo) {
		gcry_cipher_open(&tothem_sa.cry_ctx, tothem_sa.cry_algo, GCRY_CIPHER_MODE_CBC, 0);
		gcry_cipher_setkey(tothem_sa.cry_ctx, tothem_sa.enc_secret, tothem_sa.enc_secret_size);
		gcry_cipher_algo_info(tothem_sa.cry_algo, GCRYCTL_GET_BLKLEN, NULL, &(tothem_sa.ivlen));
	} else {
		tothem_sa.cry_ctx = NULL;
		tothem_sa.ivlen = 0;
		tothem_sa.blksize = 8; /* ...I hope this is rellay ok */
	}

	DEBUG(2, printf("local spi: %#08x\n", tous_sa.spi));
	DEBUG(2, printf("remote spi: %#08x\n", tothem_sa.spi));
	DEBUG(2, printf("md algo: %d crypt algo: %d\n", md_algo, cry_algo));
	DEBUG(2, printf("local addr: %#08x port: %d family: %d\n",
			tothem_sa.source.sin_addr.s_addr,
			tothem_sa.source.sin_port,
			tothem_sa.source.sin_family));
	DEBUG(2, printf("remote addr: %#08x port: %d family: %d\n",
			tothem_sa.dest.sin_addr.s_addr,
			tothem_sa.dest.sin_port,
			tothem_sa.dest.sin_family));


	vpnpeer.tun_fd = tun_fd;
	vpnpeer.tun_hwaddr = tun_hwaddr;
	vpnpeer.local_sa = &tous_sa;
	vpnpeer.remote_sa = &tothem_sa;

	do_kill = 0;
	kill_packet = kill_packet_p;
	kill_packet_size = kill_packet_size_p;
	kill_dest = kill_dest_p;

	signal(SIGHUP, killit);
	signal(SIGINT, killit);
	signal(SIGTERM, killit);
	signal(SIGXCPU, killit);
#if defined(SIGPWR)
	signal(SIGPWR, killit);
#endif

	chdir("/");

	setsid();
	if (!opt_nd) {
		pid_t pid;
		if ((pid = fork()) < 0) {
			fprintf(stderr, "Warning, could not fork the child process!\n");
		} else if (pid == 0) {
			close(0); open("/dev/null", O_RDONLY, 0666);
			close(1); open("/dev/null", O_WRONLY, 0666);
			close(2); open("/dev/null", O_WRONLY, 0666);
			openlog("vpnc", LOG_PID, LOG_DAEMON);
			write_pidfile(pidfile);
		} else {
			printf("VPNC started in background (pid: %d)...\n", (int)pid);
			exit(0);
		}
	} else {
		printf("VPNC started in foreground...\n");
		openlog("vpnc", LOG_PID, LOG_DAEMON);
	}

	vpnc_main_loop(&vpnpeer, &meth, (!opt_nd) ? pidfile : NULL);
}
