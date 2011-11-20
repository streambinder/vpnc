/* IPSec VPN client compatible with Cisco equipment.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gcrypt.h>

#include "config.h"
#include "sysdep.h"
#include "crypto.h"

static int gnutls_initialized = 0;

#define CERT_STACK_DEPTH 20

crypto_ctx *crypto_ctx_new(crypto_error **error)
{
	crypto_ctx *ctx;

	if (!gnutls_initialized) {
		if (gnutls_global_init() != 0) {
			crypto_error_set(error, 1, 0, "error initializing gnutls globals");
			return NULL;
		}
		gnutls_initialized = 1;
	}

	ctx = gnutls_calloc(1, sizeof(crypto_ctx));
	if (!ctx) {
		crypto_error_set(error, 1, ENOMEM, "not enough memory for crypto context");
		return NULL;
	}

	ctx->stack = gnutls_calloc(CERT_STACK_DEPTH, sizeof(gnutls_x509_crt_t));
	if (!ctx->stack) {
		crypto_ctx_free(ctx);
		crypto_error_set(error, 1, ENOMEM,
		                 "not enough memory for crypto certificate stack");
		ctx = NULL;
	}

	return ctx;
}

void crypto_ctx_free(crypto_ctx *ctx)
{
	if (ctx) {
		int i;

		for (i = 0; i < ctx->num; i++)
			gnutls_x509_crt_deinit(ctx->stack[i]);
		gnutls_free(ctx->stack);
		memset(ctx, 0, sizeof(crypto_ctx));
		gnutls_free(ctx);
	}
}

unsigned char *crypto_read_cert(const char *path,
                                size_t *out_len,
                                crypto_error **error)
{
	gnutls_x509_crt_t cert;
	unsigned char *data = NULL;
	gnutls_datum dt;
	size_t fsize = 0;
	int err;

	dt.data = crypto_read_file(path, &fsize, error);
	if (!dt.data)
		return NULL;

	dt.size = (unsigned int) fsize;
	if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS) {
		crypto_error_set(error, 1, ENOMEM, "not enough memory for certificate");
		goto out;
	}

	err = gnutls_x509_crt_import(cert, &dt, GNUTLS_X509_FMT_PEM);
	if (err != GNUTLS_E_SUCCESS)
		err = gnutls_x509_crt_import(cert, &dt, GNUTLS_X509_FMT_DER);
	if (err != GNUTLS_E_SUCCESS) {
		crypto_error_set(error, 1, 0, "certificate (%s) format unknown", path);
		goto out;
	}

	*out_len = 10000;
	data = malloc(*out_len);
	err = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, data, out_len);
	if (err != GNUTLS_E_SUCCESS) {
		free(data);
		*out_len = 0;
		crypto_error_set(error, 1, 0, "certificate could not be exported");
	}

out:
	if (dt.data)
		gnutls_free(dt.data);
	gnutls_x509_crt_deinit(cert);
	return data;
}

int crypto_push_cert(crypto_ctx *ctx,
                     const unsigned char *data,
                     size_t len,
                     crypto_error **error)
{
	gnutls_x509_crt_t cert;
	gnutls_datum dt;
	int err;

	if (!ctx || !data || (len <= 0)) {
		crypto_error_set(error, 1, 0, "invalid crypto context or data");
		return 1;
	}

	if (ctx->num >= CERT_STACK_DEPTH) {
		crypto_error_set(error, 1, 0, "too many certificates in the chain.");
		return 1;
	}

	gnutls_x509_crt_init (&cert);

	dt.data = (unsigned char *) data;
	dt.size = len;
	err = gnutls_x509_crt_import (cert, &dt, GNUTLS_X509_FMT_DER);
	if (err != GNUTLS_E_SUCCESS) {
		gnutls_x509_crt_deinit (cert);
		crypto_error_set(error, 1, 0, "failed to decode certificate");
		return 1;
	}

	ctx->stack[ctx->num] = cert;
	ctx->num++;
	return 0;
}

static int verify_issuer(gnutls_x509_crt_t crt,
                         gnutls_x509_crt_t issuer,
                         crypto_error **error)
{
	unsigned int output;
	time_t now = time (0);

	if (gnutls_x509_crt_verify(crt, &issuer, 1, 0, &output) < 0) {
		crypto_error_set(error, 1, 0, "failed to verify against issuer");
		return 1;
	}

	if (output & GNUTLS_CERT_INVALID) {
		if (output & GNUTLS_CERT_SIGNER_NOT_FOUND) {
			crypto_error_set(error, 1, 0, "certificate signer not found");
			return 1;
		}
		if (output & GNUTLS_CERT_SIGNER_NOT_CA) {
			crypto_error_set(error, 1, 0, "certificate signer not a CA");
			return 1;
		}
	}

	if (gnutls_x509_crt_get_activation_time(crt) > now) {
		crypto_error_set(error, 1, 0, "certificate activation in the future");
		return 1;
	}

	if (gnutls_x509_crt_get_expiration_time(crt) < now) {
		crypto_error_set(error, 1, 0, "certificate expired");
		return 1;
	}

	return 0;
}

static int verify_last(gnutls_x509_crt_t crt,
                       gnutls_x509_crt_t *ca_list,
                       size_t ca_list_size,
                       crypto_error **error)
{
	unsigned int output;
	time_t now = time (0);

	if (gnutls_x509_crt_verify (crt, ca_list, ca_list_size,
	                            GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
	                            &output) < 0) {
		crypto_error_set(error, 1, 0, "failed to verify against CA list");
		return 1;
	}

	if (output & GNUTLS_CERT_INVALID) {
		if (output & GNUTLS_CERT_SIGNER_NOT_CA) {
			crypto_error_set(error, 1, 0, "certificate signer not a CA");
			return 1;
		}
	}

	if (gnutls_x509_crt_get_activation_time(crt) > now) {
		crypto_error_set(error, 1, 0, "certificate activation in the future");
		return 1;
	}

	if (gnutls_x509_crt_get_expiration_time(crt) < now) {
		crypto_error_set(error, 1, 0, "certificate expired");
		return 1;
	}

	return 0;
}

static gnutls_x509_crt_t *load_one_ca_file(const char *path, crypto_error **error)
{
	gnutls_x509_crt_t *list = NULL;
	gnutls_x509_crt_t cert;
	gnutls_datum dt;
	size_t fsize = 0;
	int err;

	dt.data = crypto_read_file(path, &fsize, error);
	if (!dt.data)
		return NULL;

	dt.size = (unsigned int) fsize;
	if (gnutls_x509_crt_init (&cert) != GNUTLS_E_SUCCESS) {
		gnutls_free(dt.data);
		crypto_error_set(error, 1, ENOMEM, "not enough memory for certificate");
		goto out;
	}

	err = gnutls_x509_crt_import (cert, &dt, GNUTLS_X509_FMT_PEM);
	if (err != GNUTLS_E_SUCCESS)
		err = gnutls_x509_crt_import (cert, &dt, GNUTLS_X509_FMT_DER);
	gnutls_free(dt.data);
	if (err != GNUTLS_E_SUCCESS) {
		crypto_error_set(error, 1, 0, "certificate (%s) format unknown", path);
		goto out;
	}

	list = gnutls_malloc(sizeof(gnutls_x509_crt_t));
	if (!list) {
		crypto_error_set(error, 1, ENOMEM, "not enough memory for certificate list");
		goto out;
	} else
		list[0] = cert;

out:
	gnutls_x509_crt_deinit (cert);
	return list;
}

static gnutls_x509_crt_t *load_ca_list_file(const char *path,
                                            size_t *out_list_size,
                                            crypto_error **error)
{
	gnutls_x509_crt_t *list;
	gnutls_datum dt = { NULL, 0 };
	size_t fsize = 0;
	int err;
	unsigned int num = 200;

	dt.data = crypto_read_file(path, &fsize, error);
	if (!dt.data)
		return NULL;

	dt.size = (unsigned int) fsize;
	list = gnutls_malloc(sizeof(gnutls_x509_crt_t) * num);
	if (!list) {
		crypto_error_set(error, 1, ENOMEM, "not enough memory for CA list");
		goto out;
	}

	err = gnutls_x509_crt_list_import(list, &num, &dt, GNUTLS_X509_FMT_PEM, 0);
	if (err <= 0) {
		/* DER then maybe */
		gnutls_free(list);
		list = load_one_ca_file(path, error);
		if (!list)
			goto out;
		num = 1;
	} else
		num = err;  /* gnutls_x509_crt_list_import() returns # read */

	if (err < 0) {
		crypto_error_set(error, 1, 0, "importing CA list (%d)", err);
		gnutls_free(list);
		list = NULL;
	} else
		*out_list_size = num;

out:
	gnutls_free(dt.data);
	return list;
}

int crypto_verify_chain(crypto_ctx *ctx,
                        const char *ca_file,
                        const char *ca_dir,
                        crypto_error **error)
{
	int err, i, ret = 1, start = 0;
	gnutls_x509_crt_t *ca_list = NULL;
	size_t ca_list_size = 0;

	if (!ctx)
		return 1;

	if (ctx->num == 0)
		return 0;

	if (ca_file) {
		ca_list = load_ca_list_file(ca_file, &ca_list_size, error);
		if (!ca_list)
			return 1;
	} else if (ca_dir) {
		/* FIXME: Try to load all files in the directory I guess... */
		crypto_error_set(error, 1, 0, "ca_dir not yet supported");
		return 1;
	}

	/* If the server cert is self-signed, ignore it in the issuers check */
	err = gnutls_x509_crt_check_issuer(ctx->stack[0], ctx->stack[0]);
	if (err > 0)
		start++;

	/* Check each certificate against its issuer */
	for (i = start; i < ctx->num - 1; i++) {
		if (verify_issuer(ctx->stack[i], ctx->stack[i + 1], error))
			goto out;
	}

	/* Verify the last certificate */
	if (verify_last(ctx->stack[ctx->num - 1], ca_list, ca_list_size, error))
		goto out;

	ret = 0;

out:
	if (ca_list) {
		for (i = 0; i < (int) ca_list_size; i++)
			gnutls_x509_crt_deinit(ca_list[i]);
		gnutls_free(ca_list);
	}
	return ret;
}

static unsigned char *check_pkcs1_padding(unsigned char* from,
                                          size_t from_len,
                                          size_t *out_len,
                                          crypto_error **error)
{
	int i = 0;
	unsigned char *rec_hash = NULL;
	size_t hash_len = 0;

	/* No function provided to check that hash conforms to
	 * PKCS#1 1.5 padding scheme. Moreover gcrypt trim first
	 * 0 bytes */
	if (from[i++] != 0x01) {
		crypto_error_set(error, 1, 0, "hash doesn't conform to PKCS#1 padding");
		goto out;
	}

	while (from[i] != 0x00) {
		if (from[i++] != 0xFF) {
			crypto_error_set(error, 1, 0, "hash doesn't conform to PKCS#1 padding");
			goto out;
		}
	}

	i++; /* Skips 00 byte */

	if (i < 10) {
		crypto_error_set(error, 1, 0, "PKCS#1 padding too short");
		goto out;
	}

	hash_len = from_len - i;
	rec_hash = calloc(1, hash_len);
	if (!rec_hash)
		goto out;

	memcpy(rec_hash, from + i, hash_len);
	*out_len = hash_len;

out:
	return rec_hash;
}


unsigned char *crypto_decrypt_signature(crypto_ctx *ctx,
                                        const unsigned char *sig_data,
                                        size_t sig_len,
                                        size_t *out_len,
                                        unsigned int padding,
                                        crypto_error **error)
{
	unsigned char *buf = NULL, *rec_hash = NULL;
	gnutls_datum_t n = { NULL, 0 }, e = { NULL, 0 };
	int err, algo;
	gcry_sexp_t key = NULL, sig = NULL, decrypted = NULL, child = NULL;
	gcry_mpi_t n_mpi = NULL, e_mpi = NULL, sig_mpi = NULL, dec_mpi = NULL;
	size_t buf_len = 0, hash_len = 0;

	if (!ctx) {
		crypto_error_set(error, 1, 0, "invalid crypto context");
		return NULL;
	}

	if (!ctx->num) {
		crypto_error_set(error, 1, 0, "no certificates in the stack");
		return NULL;
	}

	algo = gnutls_x509_crt_get_pk_algorithm(ctx->stack[ctx->num - 1], NULL);
	if (algo != GNUTLS_PK_RSA) {
		crypto_error_set(error, 1, 0, "certificate public key algorithm not RSA");
		return NULL;
	}

	err = gnutls_x509_crt_get_pk_rsa_raw(ctx->stack[ctx->num - 1], &n, &e);
	if (err != GNUTLS_E_SUCCESS) {
		crypto_error_set(error, 1, 0, "error getting certificate public key");
		return NULL;
	}

	err = gcry_mpi_scan(&n_mpi, GCRYMPI_FMT_USG, n.data, n.size, NULL);
	if (err) {
		crypto_error_set(error, 1, 0, "invalid RSA key 'n' format");
		goto out;
	}

	err = gcry_mpi_scan(&e_mpi, GCRYMPI_FMT_USG, e.data, e.size, NULL);
	if (err) {
		crypto_error_set(error, 1, 0, "invalid RSA key 'e' format");
		goto out;
	}

	err = gcry_sexp_build(&key, NULL, "(public-key (rsa (n %m) (e %m)))", n_mpi, e_mpi);
	if (err) {
		crypto_error_set(error, 1, 0, "could not create public-key expression");
		goto out;
	}

	err = gcry_mpi_scan(&sig_mpi, GCRYMPI_FMT_USG, sig_data, sig_len, NULL);
	if (err) {
		crypto_error_set(error, 1, 0, "invalid signature format");
		goto out;
	}

	err = gcry_sexp_build(&sig, NULL, "(data (flags raw) (value %m))", sig_mpi);
	if (err) {
		crypto_error_set(error, 1, 0, "could not create signature expression");
		goto out;
	}

	/* encrypt is equivalent to public key decryption for RSA keys */
	err = gcry_pk_encrypt(&decrypted, sig, key);
	if (err) {
		crypto_error_set(error, 1, 0, "could not decrypt signature");
		goto out;
	}

	child = gcry_sexp_find_token(decrypted, "a", 1);
	if (!child) {
		crypto_error_set(error, 1, 0, "could not get decrypted signature result");
		goto out;
	}

	dec_mpi = gcry_sexp_nth_mpi(child, 1, GCRYMPI_FMT_USG);
	gcry_sexp_release(child);

	if (!dec_mpi) {
		crypto_error_set(error, 1, 0, "could not get decrypted signature result");
		goto out;
	}

	gcry_mpi_aprint(GCRYMPI_FMT_USG, &buf, &buf_len, dec_mpi);
	if (!buf) {
		crypto_error_set(error, 1, 0, "could not get extract decrypted signature");
		goto out;
	}

	switch (padding) {
	case CRYPTO_PAD_NONE:
		rec_hash = buf;
		hash_len = buf_len;
		buf = NULL;
		*out_len = (int) hash_len;
		break;
	case CRYPTO_PAD_PKCS1:
		rec_hash = check_pkcs1_padding(buf, buf_len, &hash_len, error);
		if (!rec_hash) {
			crypto_error_set(error, 1, 0, "could not get extract decrypted padded signature");
			goto out;
		}
		*out_len = (int) hash_len;
		break;
	default:
		crypto_error_set(error, 1, 0, "unknown padding mechanism %d", padding);
		break;
	}

out:
	if (buf)
		free(buf);
	if (dec_mpi)
		gcry_mpi_release(dec_mpi);
	if (decrypted)
		gcry_sexp_release(decrypted);
	if (key)
		gcry_sexp_release(key);
	if (sig)
		gcry_sexp_release(sig);
	if (sig_mpi)
		gcry_mpi_release(sig_mpi);
	if (n_mpi)
		gcry_mpi_release(n_mpi);
	if (e_mpi)
		gcry_mpi_release(e_mpi);
	if (n.data)
		gcry_free(n.data);
	if (e.data)
		gcry_free(e.data);

	return rec_hash;
}

