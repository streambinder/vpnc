/* IPSec ESP and AH support.
   Copyright (c) 1999      Pierre Beyssac
   Copyright (C) 2002      Geoffrey Keating
   Copyright (C) 2003-2004 Maurice Massar
   Copyright (C) 2004      Tomas Mraz

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
#include <poll.h>
#include <signal.h>

#ifndef __sun__
#include <err.h>
#endif

#include <gcrypt.h>
#include "sysdep.h"
#include "config.h"
#include "vpnc.h"

#define max(a,b)	((a)>(b)?(a):(b))

struct sa_desc {
	struct sa_desc *next;

	struct sockaddr_in init; /* initial and fallback remote address */
	struct sockaddr_in dest; /* current remote address */
	struct sockaddr_in source; /* local socket address we send packets from */
	unsigned char use_fallback; /* use initial address as fallback? */
	unsigned char use_dest; /* is dest address known yet? */

	unsigned long spi; /* security parameters index */
	unsigned long seq_id; /* for replay protection (not implemented) */

	/* Encryption key */
	const unsigned char *enc_secret;
	size_t enc_secret_size;
	size_t ivlen;
	/* Preprocessed encryption key */
	gcry_cipher_hd_t cry_ctx;
	int cry_algo;

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
};

/* A real ESP header (RFC 2406) */
typedef struct esp_encap_header {
	unsigned long spi; /* security parameters index */
	unsigned long seq_id; /* sequence id (unimplemented) */
	/* variable-length payload data + padding */
	/* unsigned char next_header */
	/* optional auth data */
} esp_encap_header_t;

struct encap_method {
	int fd; /* file descriptor for relevant socket */
	unsigned char *name;

	int fixed_header_size;

	/* Description of the packet being processed */
	unsigned char *buf;
	unsigned int bufsize, bufpayload, var_header_size;
	int buflen;
	struct sockaddr_in from;
	int fromlen;
	uint16_t destport;

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
void encap_espinudp_send_peer(struct encap_method *encap,
	struct peer_desc *peer, unsigned char *buf, unsigned int bufsize);
struct peer_desc *peer_find(unsigned long spi, struct encap_method *encap);
int encap_esp_recv_peer(struct encap_method *encap, struct peer_desc *peer);

/* Yuck! Global variables... */

#define MAX_HEADER 64
#define MAX_PACKET 4096
unsigned char buf[MAX_HEADER + MAX_PACKET];

struct peer_desc vpnpeer;

unsigned short ip_id;

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
u_short in_cksum(addr, len)
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
int encap_rawip_recv(struct encap_method *encap,
	unsigned char *buf, unsigned int bufsize, struct sockaddr_in *from)
{
	int r;
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
int encap_udp_recv(struct encap_method *encap,
	unsigned char *buf, unsigned int bufsize,
	struct sockaddr_in *from)
{
	int r;

	encap->fromlen = sizeof(encap->from);

	r = recvfrom(encap->fd, buf, bufsize, 0,
		(struct sockaddr *)&encap->from, &encap->fromlen);
	if (r == -1) {
		syslog(LOG_ERR, "recvfrom: %m");
		return -1;
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

struct peer_desc *encap_esp_peer_find(struct encap_method *encap)
{
	esp_encap_header_t *eh;
	eh = (esp_encap_header_t *) (encap->buf + encap->bufpayload);
	return peer_find(ntohl(eh->spi), encap);
}

/*
 * Decapsulate packet
 */
int encap_any_decap(struct encap_method *encap)
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
int tun_send_ip(struct encap_method *encap, int fd)
{
	int sent;

	sent = tun_write(fd, encap->buf, encap->buflen);
	if (sent != encap->buflen)
		syslog(LOG_ERR, "truncated in: %d -> %d\n", encap->buflen, sent);
	return 1;
}

int encap_esp_new(struct encap_method *encap, unsigned char proto)
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

int encap_espinudp_new(struct encap_method *encap, uint16_t our_port, uint16_t their_port)
{
	encap->fd = socket(PF_INET, SOCK_DGRAM, 0);
	encap->destport = their_port;

	if (encap->fd == -1) {
		perror("socket(SOCK_DGRAM)");
		return -1;
	}

	if (our_port != 0) {
		struct sockaddr_in name;

		name.sin_family = AF_INET;
		name.sin_port = our_port;
		name.sin_addr.s_addr = htonl (INADDR_ANY);
		if (bind (encap->fd, (struct sockaddr *) &name, sizeof (name)) < 0) {
			perror ("binding to udp port");
			return -1;
		}
	}

	encap->name = "ipespinudp";
	encap->recv = encap_udp_recv;
	encap->peer_find = encap_esp_peer_find;
	encap->send_peer = encap_espinudp_send_peer;
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
	int addrlen;
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
int update_sa_addr(struct sa_desc *p)
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
struct peer_desc *peer_find(unsigned long spi, struct encap_method *encap)
{
	if (vpnpeer.local_sa->spi == spi && vpnpeer.local_sa->em == encap)
		return &vpnpeer;
	syslog(LOG_ALERT, "unknown spi %ld", spi);
	return NULL;
}

/*
 * Compute HMAC for an arbitrary stream of bytes
 */
int hmac_compute(int md_algo,
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
void encap_esp_encapsulate(struct encap_method *encap,
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
	gcry_cipher_algo_info(peer->remote_sa->cry_algo, GCRYCTL_GET_BLKLEN, NULL, &pad_blksz);
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
	gcry_randomize(iv, peer->remote_sa->ivlen, GCRY_WEAK_RANDOM);
	hex_dump("iv", iv, peer->remote_sa->ivlen);
	hex_dump("auth_secret", peer->remote_sa->auth_secret, peer->remote_sa->auth_secret_size);

#if 1
	hex_dump("sending ESP packet (before crypt)", encap->buf, encap->buflen);
#endif

	{
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
	ip->ip_len = encap->buflen + (peer->remote_sa->md_algo? 12 :0);
#ifdef NEED_IPLEN_FIX
	ip->ip_len = htons(ip->ip_len);
#endif
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

	ip->ip_sum = in_cksum((u_short *) encap->buf, sizeof(struct ip));

	sent = sendto(encap->fd, encap->buf, encap->buflen, 0,
		(struct sockaddr *)&peer->remote_sa->dest, sizeof(peer->remote_sa->dest));
	if (sent == -1) {
		syslog(LOG_ERR, "sendto: %m");
		return;
	}
	if (sent != encap->buflen)
		syslog(LOG_ALERT, "truncated out (%d out of %d)", sent, encap->buflen);
}

/*
 * Encapsulate a packet in UDP ESP and send to the peer.
 * "buf" should have exactly MAX_HEADER free bytes at its beginning
 * to account for encapsulation data (not counted in "size").
 */
void encap_espinudp_send_peer(struct encap_method *encap,
	struct peer_desc *peer,
	unsigned char *buf, unsigned int bufsize)
{
	ssize_t sent;
	struct sockaddr_in destaddr;

	buf += MAX_HEADER;

	encap->buf = buf;
	encap->buflen = bufsize;

	/* Prepend our encapsulation header and new IP header */
	encap->var_header_size = (encap->fixed_header_size + peer->remote_sa->ivlen);

	encap->buf -= encap->var_header_size;
	encap->buflen += encap->var_header_size;

	encap->bufpayload = 0;

	encap_esp_encapsulate(encap, peer);

	memcpy(&destaddr, &peer->remote_sa->dest, sizeof(destaddr));
	destaddr.sin_port = encap->destport;

	sent = sendto(encap->fd, encap->buf, encap->buflen, 0,
		(struct sockaddr *)&destaddr, sizeof(destaddr));
	if (sent == -1) {
		syslog(LOG_ERR, "sendto: %m");
		return;
	}
	if (sent != encap->buflen)
		syslog(LOG_ALERT, "truncated out (%Zd out of %Zd)",
			sent, encap->buflen);
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

	gcry_cipher_algo_info(peer->local_sa->cry_algo, GCRYCTL_GET_BLKLEN, NULL, &blksz);
	if ((len % blksz) != 0) {
		syslog(LOG_ALERT,
			"payload len %d not a multiple of algorithm block size %lu", len,
			(unsigned long)blksz);
		return -1;
	}
#if 0
	printf("receiving ESP packet (before decrypt):\n");
	for (i = 0; i < len; i++)
		printf(" %02x", encap->buf[encap->bufpayload
				+ encap->fixed_header_size + encap->var_header_size + i]);
	printf("\n");
#endif

	{
		unsigned char *data;

		data = (encap->buf + encap->bufpayload
			+ encap->fixed_header_size + encap->var_header_size);
		gcry_cipher_setiv(peer->local_sa->cry_ctx, iv, peer->local_sa->ivlen);
		gcry_cipher_decrypt(peer->local_sa->cry_ctx, data, len, NULL, 0);
	}

#if 0
	printf("receiving ESP packet (after decrypt %d):\n", len);
	for (i = 0; i < len; i++)
		printf(" %02x", encap->buf[encap->bufpayload
				+ encap->fixed_header_size + encap->var_header_size + i]);
	printf("\n");
#endif

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

static void vpnc_main_loop(struct peer_desc *peer, struct encap_method *meth, int tun_fd)
{
	struct pollfd pollfds[2];

	pollfds[0].fd = tun_fd;
	pollfds[0].events = POLLIN;
	pollfds[1].fd = encap_get_fd(meth);
	pollfds[1].events = POLLIN;

	for (;;) {
		int presult;

		do {
			presult = poll(pollfds, sizeof(pollfds) / sizeof(pollfds[0]), -1);
		} while (presult == -1 && errno == EINTR);
		if (presult == -1) {
			syslog(LOG_ERR, "poll: %m");
			continue;
		}

		if (pollfds[0].revents & POLLIN) {
			int pack;

			/* Receive a packet from the tunnel interface */
			pack = tun_read(peer->tun_fd, buf + MAX_HEADER, MAX_PACKET);
			if (pack == -1) {
				syslog(LOG_ERR, "read: %m");
				continue;
			}

			if (peer->remote_sa->use_dest == 0) {
				syslog(LOG_NOTICE, "peer hasn't a known address yet");
				continue;
			}

			if (((struct ip *)(buf + MAX_HEADER))->ip_dst.s_addr
				== peer->remote_sa->dest.sin_addr.s_addr) {
				syslog(LOG_ALERT, "routing loop to %s",
					inet_ntoa(peer->remote_sa->dest.sin_addr));
				continue;
			}

			/* Encapsulate and send to the other end of the tunnel */
			encap_send_peer(peer->remote_sa->em, peer, buf, pack);

			/* Update sent packet timeout */
			peer->remote_sa->last_packet_sent = time(NULL);
		}
		if (pollfds[1].revents & POLLIN) {
			/* Receive a packet from a socket */
			struct peer_desc *peer;
			int pack;
			struct sockaddr_in from;

			pack = encap_recv(meth, buf, MAX_HEADER + MAX_PACKET, &from);
			if (pack == -1)
				continue;

			peer = encap_peer_find(meth);
			if (peer == NULL) {
				syslog(LOG_NOTICE, "unknown spi from %s", inet_ntoa(from.sin_addr));
				continue;
			}

			/* Check auth digest and/or decrypt */
			if (encap_recv_peer(meth, peer) != 0)
				continue;

			/* Check origin IP; update our copy if need be */
			if (peer->remote_sa->use_dest == 0
				|| from.sin_addr.s_addr != peer->remote_sa->dest.sin_addr.s_addr) {
				/* remote end changed address */
				char addr1[16];
				strcpy(addr1, inet_ntoa(peer->remote_sa->dest.sin_addr));
				syslog(LOG_NOTICE,
					"spi %ld: remote address changed from %s to %s",
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
				tun_send_ip(meth, peer->tun_fd);
		}
	}
}

static uint8_t *volatile kill_packet;
static size_t volatile kill_packet_size;
static struct sockaddr *volatile kill_dest;

void killit(int signum)
{
	int sock = signum; /* unused */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock >= 0) {
		sendto(sock, kill_packet, kill_packet_size, 0,
			kill_dest, sizeof(struct sockaddr_in));
		close(sock);
	}
	tun_close(oursa->tun_fd, oursa->tun_name);
	syslog(LOG_NOTICE, "terminated");
	_exit(0);
}

void write_pidfile(const char *pidfile)
{
	FILE *pf;

	if (pidfile == NULL)
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
	int tun_fd, int md_algo, int cry_algo,
	uint8_t * kill_packet_p, size_t kill_packet_size_p,
	struct sockaddr *kill_dest_p,
	uint16_t our_port, uint16_t their_port,
	const char *pidfile)
{
	struct encap_method meth;

	static struct sa_desc tous_sa, tothem_sa;
	time_t t = time(NULL);

	if (their_port != 0) {
		if (encap_espinudp_new(&meth, our_port, their_port) == -1)
			exit(1);
	} else {
		if (encap_esp_new(&meth, IPPROTO_ESP) == -1)
			exit(1);
	}

	tous_sa.next = remote_sa_list;
	remote_sa_list = &tous_sa;
	tous_sa.em = &meth;
	tous_sa.last_packet_recv = t;
	tous_sa.last_packet_sent = t;
	tous_sa.last_checkifaddr = t;
	tous_sa.md_algo = md_algo;
	tous_sa.spi = htonl(tous_spi);
	tous_sa.enc_secret = tous_key;
	gcry_cipher_algo_info(cry_algo, GCRYCTL_GET_KEYLEN, NULL, &(tous_sa.enc_secret_size));
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
	gcry_cipher_open(&tous_sa.cry_ctx, tous_sa.cry_algo, GCRY_CIPHER_MODE_CBC, 0);
	gcry_cipher_setkey(tous_sa.cry_ctx, tous_sa.enc_secret, tous_sa.enc_secret_size);
	gcry_cipher_algo_info(tous_sa.cry_algo, GCRYCTL_GET_BLKLEN, NULL, &(tous_sa.ivlen));

	tothem_sa.next = local_sa_list;
	local_sa_list = &tothem_sa;
	tothem_sa.em = &meth;
	tothem_sa.last_packet_recv = t;
	tothem_sa.last_packet_sent = t;
	tothem_sa.last_checkifaddr = t;
	tothem_sa.md_algo = md_algo;
	tothem_sa.spi = htonl(tothem_spi);
	tothem_sa.enc_secret = tothem_key;
	gcry_cipher_algo_info(cry_algo, GCRYCTL_GET_KEYLEN, NULL, &(tothem_sa.enc_secret_size));
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
	gcry_cipher_open(&tothem_sa.cry_ctx, tothem_sa.cry_algo, GCRY_CIPHER_MODE_CBC, 0);
	gcry_cipher_setkey(tothem_sa.cry_ctx, tothem_sa.enc_secret, tothem_sa.enc_secret_size);
	gcry_cipher_algo_info(tothem_sa.cry_algo, GCRYCTL_GET_BLKLEN, NULL, &(tothem_sa.ivlen));

	vpnpeer.tun_fd = tun_fd;
	vpnpeer.local_sa = &tous_sa;
	vpnpeer.remote_sa = &tothem_sa;

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
			close(0);
			close(1);
			close(2);
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

	vpnc_main_loop(&vpnpeer, &meth, tun_fd); /* never returns */
	exit(0);
}
