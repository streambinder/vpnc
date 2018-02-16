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

