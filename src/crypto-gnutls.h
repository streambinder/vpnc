/*
   IPSec VPN client compatible with Cisco equipment.

   SPDX-FileCopyrightText: 2019 Davide Pucci
   SPDX-FileCopyrightText: 2023 Jolla Ltd.

   SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VPNC_CRYPTO_GNUTLS_H
#define VPNC_CRYPTO_GNUTLS_H

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

typedef struct {
	int num;
	gnutls_x509_crt_t *stack;
} crypto_ctx;

#endif  /* VPNC_CRYPTO_GNUTLS_H */

