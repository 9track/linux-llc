/* lard.h: lan address resolution daemon defintions.
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

#ifndef _LARD_H
#define _LARD_H

#define _PATH_LARHOSTS_XML_HREF "http://www.linux-sna.org/larhosts"
#define _PATH_LARHOSTS          "/etc/larhosts.xml"

#define _PATH_LARD_XML_HREF	"http://www.linux-sna.org/lard"
#define _PATH_LARDCONF       	"/etc/lard.xml"
#define _PATH_LARDPID        	"/var/run/lard.pid"

#define _PATH_LAR_USER_TABLE	"/var/run/lar_entities"
#define _PATH_LAR_UDS           "/var/run/lar.unix"

#define LAR_DIR_TIMEOUT		50000

#define new(p)          ((p) = calloc(1, sizeof(*(p))))
#define new_s(s)        calloc(1, s)

struct lar_netent {
	struct list_head list;

	/* lard data for this entry. */
	time_t			create;
	lar_mac_t		cce_mac;

	/* saved record message. */
	lar_record_usr_t	*record;
};

struct lar_listen {
	struct list_head list;
        
        int             	listen_fd;
	struct sockaddr_llc     laddr;

	u_int8_t		allmulti;

        u_int8_t        	igivname;
        u_int8_t        	ifname[IFNAMSIZ];
        u_int8_t        	ifmac[ETH_ALEN];
        u_int32_t       	ifindex;
};

struct lar_client {
	struct list_head list;

        u_int32_t               client_fd;
        struct sockaddr_un     	client_addr;

	/* save requests here. */
	u_int8_t		af;
	u_int8_t		bf;
	u_int8_t		cf;
	u_int8_t		df;
	u_int8_t		ff;
	u_int8_t		find_cnt;
	u_int8_t		found_cnt;
	lar_find_usr_t		*find;
	lar_search_usr_t	*srch;
};

struct lar_statistics {
        int debug;              

	int garbage_ttl;
	
	struct lar_tinfo	garbage;
	struct lar_tinfo	query;
	struct lar_tinfo	solicit;
	struct lar_tinfo	advertise;
	struct lar_tinfo	find;
        
        /* event statistics... */
        unsigned long director_events;          /* total/all events */
        unsigned long director_errors;          /* general errors */
        
         /* fd statistics... */
        unsigned long open_fds;
        unsigned long wmark_fd;
        unsigned long highest_fd;
};

#define SNA_LAR_QUERY_SIZE              43
#define SNA_LAR_NOTIFY_SIZE             66

#define SNA_LAR_FIND_TIMER_EXPIRE       9
#define SNA_LAR_FIND_TIMER_MAX          20
#define SNA_LAR_FIND_COUNT              2
#define SNA_LAR_FIND_COUNT_MAX          6

#define SNA_LAR_AD_TIMER_EXPIRE         5
#define SNA_LAR_AD_TIMER_MAX            60
#define SNA_LAR_AD_COUNT                10
#define SNA_LAR_AD_COUNT_MAX            20

#define SNA_LAR_SOLICIT_TIMER_EXPIRE    10
#define SNA_LAR_SOLICIT_TIMER_MAX       20
#define SNA_LAR_QUERY_TIMER_EXPIRE      9
#define SNA_LAR_QUERY_TIMER_MAX         20

#endif	/* _LARD_H */
