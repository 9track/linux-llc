/* llcpingd.h: main header file.
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

#ifndef _LLCPINGD_H
#define _LLCPINGD_H

#define _PATH_LLCPINGD_XML_HREF  "http://www.linux-sna.org/llcping"
#define _PATH_LLCPINGDCONF       "/etc/llcpingd.xml"
#define _PATH_LLCPINGDPID        "/var/run/llcpingd.pid"

#define new(p)		((p) = calloc(1, sizeof(*(p))))
#define new_s(s)	calloc(1, s)

struct llc_listen {
        struct llc_listen *next;

	int			listen_fd;
	struct sockaddr_llc	listen_addr;

        /* information set by the configuration file. */
        u_int8_t        type;
        u_int8_t        lsap;
        u_int8_t        ifname[IFNAMSIZ];
        u_int8_t        ifmac[IFHWADDRLEN];
        u_int32_t       ifindex;
};

struct llc_data {
        struct llc_data *next;

	int			data_fd;
	struct sockaddr_llc	data_addr;

        /* information set by the configuration file. */
        u_int8_t        type;
        u_int8_t        lsap;
        u_int8_t        ifname[IFNAMSIZ];
        u_int8_t        ifmac[IFHWADDRLEN];
        u_int32_t       ifindex;
};

struct llc_statistics {
	int debug;

	/* event statistics... */
	unsigned long director_events;          /* total/all events */
        unsigned long director_errors;          /* general errors */

	 /* fd statistics... */
        unsigned long open_fds;
        unsigned long wmark_fd;
        unsigned long highest_fd;
};

#endif	/* LLCPINGD_H */
