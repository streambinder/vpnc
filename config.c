/* IPSec VPN client compatible with Cisco equipment.
   Copyright (C) 2004 Maurice Massar

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

#define _GNU_SOURCE

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>

#include "sysdep.h"
#include "config.h"
#include "vpnc.h"

/*
#include <assert.h>
#include <sys/fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <gcrypt.h>

#include "isakmp-pkt.h"
#include "math_group.h"
#include "dh.h"
*/

const char *config[LAST_CONFIG];

int opt_debug = 0;
int opt_nd;
int opt_1des;

void hex_dump(const char *str, const void *data, ssize_t len)
{
	size_t i;
	const uint8_t *p = data;

	if (opt_debug < 3)
		return;

	switch (len) {
	case UINT8:
		printf("%s: %02x\n", str, *(uint8_t *)p);
		return;
	case UINT16:
		printf("%s: %04x\n", str, *(uint16_t *)p);
		return;
	case UINT32:
		printf("%s: %08x\n", str, *(uint32_t *)p);
		return;
	}

	printf("%s:%c", str, (len <= 32) ? ' ' : '\n');
	for (i = 0; i < (size_t)len; i++) {
		if (i && !(i % 32))
			printf("\n");
		else if (i && !(i % 4))
			printf(" ");
		printf("%02x", p[i]);
	}
	printf("\n");
}

static const char *config_def_description(void)
{
	return "default value for this option";
}

static const char *config_def_ike_dh(void)
{
	return "dh2";
}

static const char *config_def_pfs(void)
{
	return "server";
}

static const char *config_def_local_port(void)
{
	return "500";
}

static const char *config_def_app_version(void)
{
	struct utsname uts;
	char *version;

	uname(&uts);
	asprintf(&version, "Cisco Systems VPN Client %s:%s", VERSION, uts.sysname);
	return version;
}

static const struct config_names_s {
	enum config_enum nm;
	const int needsArgument;
	const int lvl;
	const char *option;
	const char *name;
	const char *type;
	const char *desc;
	const char *(*get_def) (void);
} config_names[] = {
	/* Note: broken config file parser does NOT support option
	 * names where one is a prefix of another option. Needs just a bit work to
	 * fix the parser to care about ' ' or '\t' after the wanted
	 * option... */
	{
		CONFIG_NONE, 0, 0,
		"commandline option,",
		"configfile variable, ",
		"argument type",
		"description",
		config_def_description
	}, {
		CONFIG_IPSEC_GATEWAY, 1, 0,
		"--gateway",
		"IPSec gateway ",
		"<ip/hostname>",
		"IP/name of your IPSec gateway",
		NULL
	}, {
		CONFIG_IPSEC_ID, 1, 0,
		"--id",
		"IPSec ID ",
		"<ASCII string>",
		"your group name",
		NULL
	}, {
		CONFIG_IPSEC_SECRET, 1, 0,
		NULL,
		"IPSec secret ",
		"<ASCII string>",
		"your group password (cleartext, no support for obfuscated strings)",
		NULL
	}, {
		CONFIG_XAUTH_USERNAME, 1, 0,
		"--username",
		"Xauth username ",
		"<ASCII string>",
		"your username",
		NULL
	}, {
		CONFIG_XAUTH_PASSWORD, 1, 0,
		NULL,
		"Xauth password ",
		"<ASCII string>",
		"your password (cleartext, no support for obfuscated strings)",
		NULL
	}, {
		CONFIG_DOMAIN, 1, 1,
		"--domain",
		"Domain ",
		"<ASCII string>",
		"(NT-) Domain name for authentication",
		NULL
	}, {
		CONFIG_XAUTH_INTERACTIVE, 0, 1,
		"--xauth-inter",
		"Xauth interactive",
		NULL,
		"enable interactive extended authentication (for challange response auth)",
		NULL
	}, {
		CONFIG_CONFIG_SCRIPT, 1, 1,
		"--script",
		"Config Script ",
		"<command>",
		"command is executed using system() to configure the interface,\n"
		"routing and so on. Device name, IP, etc. are passed using enviroment\n"
		"variables, see README. This script is executed right after ISAKMP is\n"
		"done, but befor tunneling is enabled.\n",
		sysdep_config_script
	}, {
		CONFIG_IKE_DH, 1, 1,
		"--dh",
		"IKE DH Group ",
		"<dh1/dh2/dh5>",
		"name of the IKE DH Group",
		config_def_ike_dh
	}, {
		CONFIG_IPSEC_PFS, 1, 1,
		"--pfs",
		"Perfect Forward Secrecy ",
		"<nopfs/dh1/dh2/dh5/server>",
		"Diffie-Hellman group to use for PFS",
		config_def_pfs
	}, {
		CONFIG_ENABLE_1DES, 0, 1,
		"--enable-1des",
		"Enable Single DES",
		NULL,
		"enables weak single DES encryption",
		NULL
	}, {
		CONFIG_VERSION, 1, 1,
		"--application-version",
		"Application version ",
		"<ASCII string>",
		"Application Version to report",
		config_def_app_version
	}, {
		CONFIG_IF_NAME, 1, 1,
		"--ifname",
		"Interface name ",
		"<ASCII string>",
		"visible name of the TUN interface",
		NULL
	}, {
		CONFIG_DEBUG, 1, 1,
		"--debug",
		"Debug ",
		"<0/1/2/3/99>",
		"Show verbose debug messages",
		NULL
	}, {
		CONFIG_ND, 0, 1,
		"--no-detach",
		"No Detach",
		NULL,
		"Don't detach from the console after login",
		NULL
	}, {
		CONFIG_PID_FILE, 1, 1,
		"--pid-file",
		"Pidfile ",
		"<filename>",
		"store the pid of background process in <filename>",
		NULL
	}, {
		CONFIG_LOCAL_PORT, 1, 1,
		"--local-port",
		"Local Port ",
		"<0-65535>",
		"local ISAKMP port number to use (0 == use random port)",
		config_def_local_port
	}, {
		CONFIG_NON_INTERACTIVE, 0, 1,
		"--non-inter",
		"Noninteractive",
		NULL,
		"Don't ask anything, exit on missing options",
		NULL
	}, {
		0, 0, 0, NULL, NULL, NULL, NULL, NULL
	}
};

static void read_config_file(char *name, const char **configs, int missingok)
{
	FILE *f;
	char *line = NULL;
	ssize_t line_length = 0;
	int linenum = 0;

	f = fopen(name, "r");
	if (missingok && f == NULL && errno == ENOENT)
		return;
	if (f == NULL)
		error(1, errno, "couldn't open `%s'", name);
	for (;;) {
		ssize_t llen;
		int i;

		llen = getline(&line, &line_length, f);
		if (llen == -1 && feof(f))
			break;
		if (llen == -1)
			error(1, errno, "reading `%s'", name);
		if (line[llen - 1] == '\n')
			line[llen - 1] = 0;
		linenum++;
		for (i = 0; config_names[i].name != NULL; i++) {
			if (config_names[i].nm == CONFIG_NONE)
				continue;
			if (strncasecmp(config_names[i].name, line,
					strlen(config_names[i].name)) == 0) {
				// boolean implementation, using harmles pointer targets as true
				if (!config_names[i].needsArgument) {
					configs[config_names[i].nm] = config_names[i].name;
					break;
				}
				if (configs[config_names[i].nm] == NULL)
					configs[config_names[i].nm] =
						strdup(line + strlen(config_names[i].name));
				if (configs[config_names[i].nm] == NULL)
					error(1, errno, "can't allocate memory");
				break;
			}
		}
		if (config_names[i].name == NULL && line[0] != '#' && line[0] != 0)
			error(0, 0, "warning: unknown configuration directive in %s at line %d",
				name, linenum);
	}
}

static void print_desc(const char *pre, const char *text)
{
	const char *p, *q;

	for (p = text, q = strchr(p, '\n'); q; p = q+1, q = strchr(p, '\n'))
		printf("%s%.*s\n", pre, q-p, p);

	if (*p != '\0')
		printf("%s%s\n", pre, p);
}

static void print_usage(char *argv0, int long_help)
{
	int c;

	printf("Usage: %s [--version] [--print-config] [--help] [--long-help] [options] [config file]\n\n",
		argv0);
	printf("Legend:\n");
	for (c = 0; config_names[c].name != NULL; c++) {
		if (config_names[c].lvl > long_help)
			continue;

		printf("  %s %s\n"
			"  %s%s\n",
			(config_names[c].option == NULL ? "(configfile only option)" :
				config_names[c].option),
			((config_names[c].type == NULL || config_names[c].option == NULL) ?
				"" : config_names[c].type),
			config_names[c].name,
			(config_names[c].type == NULL ? "" : config_names[c].type));
		print_desc("      ", config_names[c].desc);

		if (config_names[c].get_def != NULL)
			printf("    Default: %s\n", config_names[c].get_def());

		printf("\n");
	}
	printf("Report bugs to vpnc@unix-ag.uni-kl.de\n");
}

static void print_version(void)
{
	unsigned int i;

	printf("vpnc version " VERSION "\n");
	printf("Copyright (C) 2002-2004 Geoffrey Keating, Maurice Massar\n");
	printf("vpnc comes with NO WARRANTY, to the extent permitted by law.\n"
		"You may redistribute copies of vpnc under the terms of the GNU General\n"
		"Public License.  For more information about these matters, see the files\n"
		"named COPYING.\n");
	printf("\n");

	printf("Supported DH-Groups:");
	for (i = 0; supp_dh_group[i].name != NULL; i++)
		printf(" %s", supp_dh_group[i].name);
	printf("\n");

	printf("Supported Hash-Methods:");
	for (i = 0; supp_hash[i].name != NULL; i++)
		printf(" %s", supp_hash[i].name);
	printf("\n");

	printf("Supported Encryptions:");
	for (i = 0; supp_crypt[i].name != NULL; i++)
		printf(" %s", supp_crypt[i].name);
	printf("\n");
}

void do_config(int argc, char **argv)
{
	char *s;
	int i, c, known, s_len;
	int print_config = 0;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-') {
			read_config_file(argv[i], config, 0);
			continue;
		}

		known = 0;

		for (c = 0; config_names[c].name != NULL && !known; c++) {
			if (config_names[c].option == NULL
				|| config_names[c].nm == CONFIG_NONE
				|| strncmp(argv[i], config_names[c].option,
					strlen(config_names[c].option)) != 0)
				continue;

			s = NULL;

			known = 1;
			if (argv[i][strlen(config_names[c].option)] == '=')
				s = argv[i] + strlen(config_names[c].option) + 1;
			else if (argv[i][strlen(config_names[c].option)] == 0) {
				if (config_names[c].needsArgument) {
					if (i + 1 < argc)
						s = argv[++i];
					else
						known = 0;
				} else
					s = argv[i]; /* no arg, fill in something */
			} else
				known = 0;
			if (known)
				config[config_names[c].nm] = s;
		}

		if (!known && strcmp(argv[i], "--version") == 0) {
			print_version();
			exit(0);
		}
		if (!known && strcmp(argv[i], "--print-config") == 0) {
			print_config = 1;
			known = 1;
		}
		if (!known && strcmp(argv[i], "--help") == 0) {
			print_usage(argv[0], 0);
			exit(0);
		}
		if (!known && strcmp(argv[i], "--long-help") == 0) {
			print_usage(argv[0], 1);
			exit(0);
		}
		if (!known) {
			printf("%s: unknown option %s\n\n", argv[0], argv[i]);

			print_usage(argv[0], 1);
			exit(1);
		}
	}

	read_config_file("/etc/vpnc/default.conf", config, 1);
	read_config_file("/etc/vpnc.conf", config, 1);

	if (!print_config)
		for (i = 0; config_names[i].name != NULL; i++)
			if (!config[config_names[i].nm] && i != CONFIG_NONE
				&& config_names[i].get_def != NULL)
				config[config_names[i].nm] = config_names[i].get_def();

	opt_debug = (config[CONFIG_DEBUG]) ? atoi(config[CONFIG_DEBUG]) : 0;
	opt_nd = (config[CONFIG_ND]) ? 1 : 0;
	opt_1des = (config[CONFIG_ENABLE_1DES]) ? 1 : 0;

	if (opt_debug >= 99) {
		printf("WARNING! active debug level is >= 99, output includes username and password (hex encoded)\n");
		fprintf(stderr,
			"WARNING! active debug level is >= 99, output includes username and password (hex encoded)\n");
	}

	for (i = 0; i < LAST_CONFIG; i++) {
		if (config[i] != NULL || config[CONFIG_NON_INTERACTIVE] != NULL)
			continue;
		if (config[CONFIG_XAUTH_INTERACTIVE] && i == CONFIG_XAUTH_PASSWORD)
			continue;
		
		s = NULL;
		s_len = 0;

		switch (i) {
		case CONFIG_IPSEC_GATEWAY:
			printf("Enter IPSec gateway address: ");
			break;
		case CONFIG_IPSEC_ID:
			printf("Enter IPSec ID for %s: ", config[CONFIG_IPSEC_GATEWAY]);
			break;
		case CONFIG_IPSEC_SECRET:
			printf("Enter IPSec secret for %s@%s: ",
				config[CONFIG_IPSEC_ID], config[CONFIG_IPSEC_GATEWAY]);
			break;
		case CONFIG_XAUTH_USERNAME:
			printf("Enter username for %s: ", config[CONFIG_IPSEC_GATEWAY]);
			break;
		case CONFIG_XAUTH_PASSWORD:
			printf("Enter password for %s@%s: ",
				config[CONFIG_XAUTH_USERNAME],
				config[CONFIG_IPSEC_GATEWAY]);
			break;
		}
		fflush(stdout);
		switch (i) {
		case CONFIG_IPSEC_SECRET:
		case CONFIG_XAUTH_PASSWORD:
			s = strdup(getpass(""));
			break;
		case CONFIG_IPSEC_GATEWAY:
		case CONFIG_IPSEC_ID:
		case CONFIG_XAUTH_USERNAME:
			getline(&s, &s_len, stdin);
		}
		if (s != NULL && s[strlen(s) - 1] == '\n')
			s[strlen(s) - 1] = 0;
		config[i] = s;
	}

	if (print_config) {
		fprintf(stderr, "vpnc.conf:\n\n");
		for (i = 0; config_names[i].name != NULL; i++) {
			if (config[config_names[i].nm] == NULL)
				continue;
			printf("%s%s\n", config_names[i].name,
				config_names[i].needsArgument ?
					config[config_names[i].nm] : "");
		}
		exit(0);
	}

	if (!config[CONFIG_IPSEC_GATEWAY])
		error(1, 0, "missing IPSec gatway address");
	if (!config[CONFIG_IPSEC_ID])
		error(1, 0, "missing IPSec ID");
	if (!config[CONFIG_IPSEC_SECRET])
		error(1, 0, "missing IPSec secret");
	if (!config[CONFIG_XAUTH_USERNAME])
		error(1, 0, "missing Xauth username");
	if (!config[CONFIG_XAUTH_PASSWORD] && !config[CONFIG_XAUTH_INTERACTIVE])
		error(1, 0, "missing Xauth password");
	if (get_dh_group_ike() == NULL)
		error(1, 0, "IKE DH Group \"%s\" unsupported\n", config[CONFIG_IKE_DH]);
	if (get_dh_group_ipsec(-1) == NULL)
		error(1, 0, "Perfect Forward Secrecy \"%s\" unsupported\n",
			config[CONFIG_IPSEC_PFS]);
	if (get_dh_group_ike()->ike_sa_id == 0)
		error(1, 0, "IKE DH Group must not be nopfs\n");

	return;
}
