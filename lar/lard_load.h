/* lardd_load.h: loader header file.
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

#ifndef _LARDD_LOAD_H
#define _LARDD_LOAD_H

#define next_arg(X)     (*X = *X + 1)

struct wordmap {
        const char *word;
        int val;
};

struct lar_tinfo {
	struct lar_tinfo *next;

	u_int8_t	name[30];
	u_int8_t	secs;
	u_int8_t	count;
};

struct lar_linfo {
	struct lar_linfo *next;

	u_int8_t	allmulti;
	u_int8_t	igivname;
	u_int8_t	ifname[IFNAMSIZ];
	u_int8_t	ifmac[ETH_ALEN];
	u_int32_t	ifindex;
};

/* This structure describes global (ie., server-wide) parameters.
 */
typedef struct {
        int debug_level;

	u_int8_t lsap;

	struct lar_linfo *ll;
	struct lar_tinfo *tl;
} global;

extern int load_config_file(char *cfile);
extern int load_config(global *ginfo);
extern int lar_load_listen(struct lar_linfo *listen);
extern int lar_load_unix(void);
extern int lar_load_timer(void);
#endif	/* _LARD_LOAD_H */
