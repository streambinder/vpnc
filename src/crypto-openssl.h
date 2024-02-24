/*
   IPSec VPN client compatible with Cisco equipment.

   SPDX-FileCopyrightText: 2019 Davide Pucci

   SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPENSSL_GPL_VIOLATION
#error "openssl support cannot be built without defining OPENSSL_GPL_VIOLATION"
#endif

#ifndef __CRYPTO_OPENSSL_H__
#define __CRYPTO_OPENSSL_H__

#include <openssl/x509.h>
#include <openssl/err.h>

typedef struct {
	STACK_OF(X509) *stack;
} crypto_ctx;

#endif  /* __CRYPTO_OPENSSL_H__ */

