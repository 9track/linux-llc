/* llcpingd_load.h: loader header file.
 *
 * Author:
 * Jay Schulist         <jschlst@samba.org>
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

#ifndef _LLCPINGD_LOAD_H
#define _LLCPINGD_LOAD_H

#define next_arg(X)     (*X = *X + 1)

struct wordmap {
        const char *word;
        int val;
};

struct llc_linfo {
	struct llc_linfo *next;

	/* information set by the configuration file. */
	u_int8_t	type;
	u_int8_t	lsap;
	u_int8_t	ifname[IFNAMSIZ];
	u_int8_t	ifmac[ETH_ALEN];
	u_int32_t       ifindex;
};

/* This structure describes global (ie., server-wide) parameters.
 */
typedef struct {
        int debug_level;

	struct llc_linfo *ll;
} global;

extern int load_config_file(char *cfile);
extern int load_config(global *ginfo);
extern int llc_load_listener(struct llc_linfo *l);
#endif	/* _LLCPINGD_LOAD_H */
