/* llcdb.h: common structures and definitions for llcdb.
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

#ifndef _LLCDB_H
#define _LLCDB_H

/* absolute file name for llc network data base files. */
#define _PATH_LLCHOSTS		"/etc/llchosts.xml"
#define _PATH_LLCHOSTS_XML_HREF "http://www.linux-sna.org/llchosts"

struct llchostent {
	char *lh_name;		/* offical name of host. */
	char *lh_addr;          /* offical address of host. */
	int lh_addrtype;	/* llc host address type. */
	int lh_length;		/* length of address. */
};

struct llcdbhost {
	struct llcdbhost *next;
	struct llchostent host;
};

extern struct llchostent *getllchostbyname(const char *name);
extern struct llchostent *getllchostbyaddr(const void *addr, 
	socklen_t len, int type);

#endif	/* _LLCDB_H */
