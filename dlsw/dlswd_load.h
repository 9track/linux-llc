/* dlsw_load.h: loader header file.
 *
 * Written by Jay Schulist <jschlst@samba.org>
 * Copyright (c) 2001 by Jay Schulist <jschlst@samba.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * None of the authors or maintainers or their employers admit
 * liability nor provide warranty for any of this software.
 * This material is provided "as is" and at no charge.
 */

#ifndef _DLSW_LOAD_H
#define _DLSW_LOAD_H

#define next_arg(X)     (*X = *X + 1)

struct wordmap {
        const char *word;
        int val;
};

struct dlsw_partner_info {
	struct list_head list;

	u_int32_t	connect_tries;
	
	struct in_addr	ip;

	u_int8_t	direction;
	u_int8_t	version;
	u_int16_t	read_port;
	u_int16_t	write_port;
};

struct dlsw_listen_info {
	struct list_head list;

	u_int8_t        ifname[IFNAMSIZ];
        u_int8_t        ifmac[ETH_ALEN];
        u_int32_t       ifindex;

	u_int8_t	sna;
	u_int8_t	**sna_sap_list;

	u_int8_t	netbios;
	u_int8_t	**netbios_sap_list;

	u_int8_t	mac_exclusive;
	u_int8_t	netbios_exclusive;

	dlsw_mac_addr_t         **user_mac_addr_list;
        dlsw_netbios_name_t     **user_netbios_name_list;
};

struct dlsw_ssp_info {
	struct list_head list;

	u_int8_t	version;
	u_int16_t	read_port;
	u_int16_t	write_port;
	u_int8_t	tcpconn;
	u_int32_t	window;
};

/* This structure describes global (ie., server-wide) parameters.
 */
typedef struct {
        int debug_level;

	struct list_head ssp_list;
	struct list_head listen_list;
	struct list_head partner_list;
} global;

extern int dlsw_load_user_table(void);
extern int dlsw_load_local_ssp(struct dlsw_ssp_info *ssp);
extern int dlsw_load_listen(struct dlsw_listen_info *listen);
extern int dlsw_load_partner(struct dlsw_partner_info *partner);
extern int load_config_file(char *cfile);
extern int load_config(global *ginfo);
#endif	/* _DLSW_LOAD_H */
