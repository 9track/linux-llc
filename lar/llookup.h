/* llookup.h: Lan address resolution client defintions.
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

#ifndef _LLOOKUP_H
#define _LLOOKUP_H

#define new(p)          ((p) = calloc(1, sizeof(*(p))))
#define new_s(s)        calloc(1, s)

struct wordmap {
        const char *word;
        int val;
};

struct llookup_netid {
        u_int8_t net[9];
        u_int8_t name[9];
};

struct llookup_snpa {
	struct llookup_snpa *next;
	lar_snpa_t a;
};

struct llookup_group {
	struct llookup_group *next;
	lar_group_t g;
};

struct llookup_options {
	u_int8_t		type;
	u_int32_t 		rtcap;
	struct llookup_netid	netid;
	struct llookup_snpa 	*snpa;
	struct llookup_group	*group;
};

#endif	/* _LLOOKUP_H */
