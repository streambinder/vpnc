/* IPSec VPN client compatible with Cisco equipment.
   Copyright (C) 2004-2005 Maurice Massar

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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <unistd.h>
#include <inttypes.h>

enum config_enum {
	CONFIG_NONE,
	CONFIG_SCRIPT,
	CONFIG_DEBUG,
	CONFIG_DOMAIN,
	CONFIG_ENABLE_1DES,
	CONFIG_ND,
	CONFIG_NON_INTERACTIVE,
	CONFIG_PID_FILE,
	CONFIG_LOCAL_PORT,
	CONFIG_VERSION,
	CONFIG_IF_NAME,
	CONFIG_IKE_DH,
	CONFIG_IPSEC_PFS,
	CONFIG_IPSEC_GATEWAY,
	CONFIG_IPSEC_ID,
	CONFIG_IPSEC_SECRET,
	CONFIG_IPSEC_SECRET_OBF,
	CONFIG_XAUTH_USERNAME,
	CONFIG_XAUTH_PASSWORD,
	CONFIG_XAUTH_PASSWORD_OBF,
	CONFIG_XAUTH_INTERACTIVE,
	CONFIG_UDP_ENCAP,
	CONFIG_UDP_ENCAP_PORT,
	CONFIG_DISABLE_NATT,
	CONFIG_FORCE_NATT,
	CONFIG_VENDOR,
	LAST_CONFIG
};

enum hex_dump_enum {
	UINT8 = -1,
	UINT16 = -2,
	UINT32 = -4
};

enum vendor_enum {
	CISCO,
	NETSCREEN
};

extern const char *config[LAST_CONFIG];

extern enum vendor_enum opt_vendor;
extern int opt_debug;
extern int opt_nd;
extern int opt_1des;
extern int opt_udpencap;
extern uint16_t opt_udpencapport;

#define DEBUG(lvl, a) do {if (opt_debug >= (lvl)) {a;}} while (0)

extern void hex_dump(const char *str, const void *data, ssize_t len);
extern void do_config(int argc, char **argv);
extern int hex2bin(const char *str, char **bin, int *len);
extern int deobfuscate(char *ct, int len, const char **resp, char *reslenp);

#endif
