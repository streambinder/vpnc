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

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdarg.h>

typedef struct {
	int code;
	int err;
	char *msg;
} crypto_error;

void crypto_error_set(crypto_error **error, int code, int in_errno, const char *fmt, ...);

void crypto_error_free(crypto_error *error);

void crypto_error_clear(crypto_error **error);

void crypto_call_error(crypto_error *err);

unsigned char *crypto_read_file(const char *path, size_t *out_len, crypto_error **error);

#if CRYPTO_GNUTLS
#include "crypto-gnutls.h"
#elif CRYPTO_OPENSSL
#include "crypto-openssl.h"
#else
#error "no crypto library defined"
#endif

#define CRYPTO_PAD_NONE  0
#define CRYPTO_PAD_PKCS1 1

/**
 * crypto_push_cert:
 *
 * Allocates a crypto context with the resources necessary for the specific
 * crypto library being used.
 *
 * Returns: a valid crypto context, or #NULL on error
 **/
crypto_ctx *crypto_ctx_new(crypto_error **error);

/**
 * crypto_ctx_free:
 * @ctx: a valid crypto context created with crypto_ctx_new()
 *
 * Frees resources allocated by crypo_ctx_new().
 **/
void crypto_ctx_free(crypto_ctx *ctx);

/**
 * crypto_read_cert:
 * @path: path to certificate file in either PEM or DER format
 * @out_len: length of raw certificate data
 * @error: return location for an error
 *
 * Loads a certificate and returns the binary ASN certificate data;
 *
 * Returns: certificate data on success, NULL on error
 **/
unsigned char *crypto_read_cert(const char *path,
                                size_t *out_len,
                                crypto_error **error);

/**
 * crypto_push_cert:
 * @ctx: a valid crypto context created with crypto_ctx_new()
 * @data: buffer containing raw certificate data
 * @len: length of raw certificate data
 * @error: return location for an error
 *
 * Pushes the given certificate onto the context's certificate stack.
 *
 * Returns: 0 on success, 1 on error
 **/
int crypto_push_cert(crypto_ctx *ctx,
                     const unsigned char *data,
                     size_t len,
                     crypto_error **error);

/**
 * crypto_verify_chain:
 * @ctx: a valid crypto context created with crypto_ctx_new()
 * @ca_file: path of a CA certificate file to use for verification of the
 *           certificate stack.  File may be a PEM-encoded file containing
 *           multiple CA certificates.  @ca_file is preferred over @ca_dir
 * @ca_dir: directory containing CA certificates to use for verification of the
 *          certificate stack
 * @error: return location for an error
 *
 * Verifies the certificate stack previously built with crypto_push_cert() using
 * the supplied CA certificates or certificate locations.
 *
 * Returns: 0 on success, 1 on error
 **/
int crypto_verify_chain(crypto_ctx *ctx,
                        const char *ca_file,
                        const char *ca_dir,
                        crypto_error **error);

/**
 * crypto_decrypt_signature:
 * @ctx: a valid crypto context created with crypto_ctx_new()
 * @sig_data: encrypted signature data
 * @sig_len: length of encrypted signature data
 * @out_len: size of decrypted signature data
 * @error: return location for an error
 *
 * Recovers the message digest stored in @sig_data using the public key of the
 * last certificate on the certificate stack
 *
 * Returns: decrypted message digest, or #NULL on error
 **/
unsigned char *crypto_decrypt_signature(crypto_ctx *ctx,
                                        const unsigned char *sig_data,
                                        size_t sig_len,
                                        size_t *out_hash_len,
                                        unsigned int padding,
                                        crypto_error **error);

#endif  /* __CRYPTO_H__ */

