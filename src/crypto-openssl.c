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
#include <openssl/pem.h>
#include "config.h"
#include "sysdep.h"
#include "crypto.h"

crypto_ctx *crypto_ctx_new(crypto_error **error)
{
	crypto_ctx *ctx;

	ctx = malloc(sizeof(crypto_ctx));
	if (!ctx) {
		crypto_error_set(error, 1, ENOMEM,
		                 "not enough memory for crypto context");
		return NULL;
	}

	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	memset(ctx, 0, sizeof(crypto_ctx));
	ctx->stack = sk_X509_new_null();
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
		if (ctx->stack)
			sk_X509_free(ctx->stack);

		memset(ctx, 0, sizeof(crypto_ctx));
		free(ctx);
	}
}

static int password_cb(char *buf, int size, int rwflag, void *userdata)
{
	/* Dummy callback to ensure openssl doesn't prompt for a password */
	return 0;
}

unsigned char *crypto_read_cert(const char *path,
                                size_t *out_len,
                                crypto_error **error)
{
	FILE *fp;
	X509 *cert = NULL;
	unsigned char *data = NULL, *p;

	fp = fopen(path, "r");
	if (!fp) {
		crypto_error_set(error, 1, 0, "certificate (%s) could not be opened", path);
		return NULL;
	}

	cert = PEM_read_X509(fp, NULL, password_cb, NULL);
	fclose (fp);

	if (!cert) {
		/* Try DER then */
		p = data = crypto_read_file(path, out_len, error);
		if (!data || !*out_len) {
			crypto_error_set(error, 1, 0, "could not read certificate %s", path);
			return NULL;
		}

		cert = d2i_X509(NULL, (const unsigned char **) &p, (int) (*out_len));
		if (!cert) {
			free(data);
			crypto_error_set(error, 1, 0, "could not allocate memory for certificate");
			return NULL;
		}

		return data;
	}

	/* Get length of DER data */
	*out_len = i2d_X509(cert, NULL);
	if (!*out_len) {
		crypto_error_set(error, 1, 0, "invalid certificate length");
		goto out;
	}

	p = data = malloc(*out_len);
	if (!data) {
		crypto_error_set(error, 1, 0, "could not allocate memory for certificate");
		goto out;
	}

	/* Encode the certificate to DER */
	*out_len = i2d_X509(cert, &p);
	if (!*out_len) {
		crypto_error_set(error, 1, 0, "could not export certificate data");
		if (data) {
			free(data);
			data = NULL;
		}
		goto out;
	}

out:
	if (cert)
		X509_free(cert);
	return data;
}

int crypto_push_cert(crypto_ctx *ctx,
                     const unsigned char *data,
                     size_t len,
                     crypto_error **error)
{
	X509 *cert = NULL;

	if (!ctx || !data || (len <= 0)) {
		crypto_error_set(error, 1, 0, "invalid crypto context or data");
		return 1;
	}

	/* convert the certificate to an openssl-X509 structure and push it onto the chain stack */
	cert = d2i_X509(NULL, &data, (int) len);
	if (!cert) {
		ERR_print_errors_fp(stderr);
		crypto_error_set(error, 1, 0, "failed to decode certificate");
		return 1;
	}
	sk_X509_push(ctx->stack, cert);
	return 0;
}

int crypto_verify_chain(crypto_ctx *ctx,
                        const char *ca_file,
                        const char *ca_dir,
                        crypto_error **error)
{
	X509		*x509;
	X509_STORE	*store = NULL;
	X509_LOOKUP	*lookup = NULL;
	X509_STORE_CTX	*verify_ctx = NULL;
	int             ret = 1;

	if (!ctx) {
		crypto_error_set(error, 1, 0, "invalid crypto context");
		return 1;
	}

	x509 = sk_X509_value(ctx->stack, sk_X509_num(ctx->stack) - 1);
	if (x509 == NULL) {
		ERR_print_errors_fp (stderr);
		crypto_error_set(error, 1, 0, "no certificates in the stack");
		return 1;
	}

	/* BEGIN - verify certificate chain */
	/* create the cert store */
	if (!(store = X509_STORE_new())) {
		crypto_error_set(error, 1, 0, "error creating X509_STORE object");
		return 1;
	}
	/* load the CA certificates */
	if (X509_STORE_load_locations (store, ca_file, ca_dir) != 1) {
		crypto_error_set(error, 1, 0, "error loading the CA file (%s) "
		                 "or directory (%s)", ca_file, ca_dir);
		goto out;
	}
	if (X509_STORE_set_default_paths (store) != 1) {
		crypto_error_set(error, 1, 0, "error loading the system-wide CA"
		                 " certificates");
		goto out;
	}

#if 0
	/* check CRLs */
	/* add the corresponding CRL for each CA in the chain to the lookup */
#define CRL_FILE "root-ca-crl.crl.pem"

	if (!(lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()))) {
		crypto_error_set(error, 1, 0, "error creating X509 lookup object.");
		goto out;
	}
	if (X509_load_crl_file(lookup, CRL_FILE, X509_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		crypto_error_set(error, 1, 0, "error reading CRL file");
		goto out;
	}
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif /* 0 */

	/* create a verification context and initialize it */
	if (!(verify_ctx = X509_STORE_CTX_new ())) {
		crypto_error_set(error, 1, 0, "error creating X509_STORE_CTX object");
		goto out;
	}
	/* X509_STORE_CTX_init did not return an error condition in prior versions */
	if (X509_STORE_CTX_init (verify_ctx, store, x509, ctx->stack) != 1) {
		crypto_error_set(error, 1, 0, "error intializing verification context");
		goto out;
	}

	/* verify the certificate */
	if (X509_verify_cert(verify_ctx) != 1) {
		ERR_print_errors_fp(stderr);
		crypto_error_set(error, 2, 0, "error verifying the certificate "
		                 "chain");
		goto out;
	}

	ret = 0;

out:
	if (lookup)
		X509_LOOKUP_free(lookup);
	if (store)
		X509_STORE_free(store);
	if (verify_ctx)
		X509_STORE_CTX_free(verify_ctx);
	return ret;
}

unsigned char *crypto_decrypt_signature(crypto_ctx *ctx,
                                        const unsigned char *sig_data,
                                        size_t sig_len,
                                        size_t *out_len,
                                        unsigned int padding,
                                        crypto_error **error)
{
	X509		*x509;
	EVP_PKEY	*pkey = NULL;
	RSA		*rsa;
	unsigned char	*hash = NULL;
	int             tmp_len = -1, ossl_pad;

	*out_len = 0;

	if (!ctx) {
		crypto_error_set(error, 1, 0, "invalid crypto context");
		return NULL;
	}

	x509 = sk_X509_value(ctx->stack, sk_X509_num(ctx->stack) - 1);
	if (x509 == NULL) {
		ERR_print_errors_fp (stderr);
		crypto_error_set(error, 1, 0, "no certificates in the stack");
		return NULL;
	}

	pkey = X509_get_pubkey(x509);
	if (pkey == NULL) {
		ERR_print_errors_fp (stderr);
		crypto_error_set(error, 1, 0, "error getting certificate public key");
		return NULL;
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		ERR_print_errors_fp (stderr);
		crypto_error_set(error, 1, 0, "error getting public key RSA");
		goto out;
	}

	hash = calloc(1, RSA_size(rsa));
	if (!hash) {
		crypto_error_set(error, 1, 0, "not enough memory to decrypt signature");
		goto out;
	}

	switch (padding) {
	case CRYPTO_PAD_NONE:
		ossl_pad = RSA_NO_PADDING;
		break;
	case CRYPTO_PAD_PKCS1:
		ossl_pad = RSA_PKCS1_PADDING;
		break;
	default:
		crypto_error_set(error, 1, 0, "unknown padding mechanism %d", padding);
		goto out;
	}

	tmp_len = RSA_public_decrypt(sig_len, sig_data, hash, rsa, ossl_pad);
	if (tmp_len > 0) {
		*out_len = (size_t) tmp_len;
	} else {
		ERR_print_errors_fp (stderr);
		crypto_error_set(error, 1, 0, "could not decrypt signature");
		free(hash);
		hash = NULL;
	}

out:
	if (pkey)
		EVP_PKEY_free(pkey);
	return hash;
}

