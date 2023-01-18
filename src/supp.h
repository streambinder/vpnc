/*
   Algorithm support checks

   SPDX-FileCopyrightText: 2005 Maurice Massar
   SPDX-FileCopyrightText: 2006 Dan Villiom Podlaski Christiansen
   SPDX-FileCopyrightText: 2023 Jolla Ltd.

   SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VPNC_SUPP_H
#define VPNC_SUPP_H

enum supp_algo_key {
	SUPP_ALGO_NAME,
	SUPP_ALGO_MY_ID,
	SUPP_ALGO_IKE_SA,
	SUPP_ALGO_IPSEC_SA
};

enum algo_group {
	SUPP_ALGO_DH_GROUP,
	SUPP_ALGO_HASH,
	SUPP_ALGO_CRYPT,
	SUPP_ALGO_AUTH
};

typedef struct {
	const char *name;
	int my_id, ike_sa_id, ipsec_sa_id;
	int keylen;
} supported_algo_t;

extern const supported_algo_t supp_dh_group[];
extern const supported_algo_t supp_hash[];
extern const supported_algo_t supp_crypt[];
extern const supported_algo_t supp_auth[];

extern const supported_algo_t *get_algo(enum algo_group what, enum supp_algo_key key, int id, const char *name, int keylen);
extern const supported_algo_t *get_dh_group_ike(void);
extern const supported_algo_t *get_dh_group_ipsec(int server_setting);

#endif /* VPNC_SUPP_H */
