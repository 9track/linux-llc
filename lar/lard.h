/* lard.h: lan address resolution daemon defintions.
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

#ifndef _LARD_H
#define _LARD_H

#define _PATH_LARD_XML_HREF	"http://www.linux-sna.org/lard"
#define _PATH_LARDCONF       	"/etc/lard.xml"
#define _PATH_LARDPID        	"/var/run/lard.pid"

#define _PATH_LAR_UDS           "/var/run/lar.unix"

#define new(p)          ((p) = calloc(1, sizeof(*(p))))
#define new_s(s)        calloc(1, s)

struct lar_netent {
	struct list_head list;

	/* lard data for this entry. */
	time_t		create;
	lar_mac_t	cce_mac;

	/* data from the advertisement/record. */
	lar_netid_t 	netid;
	lar_name_t	name;
	lar_rtcap_t	rtcap;
	lar_group_t	*group_list[20];
	lar_snpa_t	*snpa_list[20];
};

struct lar_listen {
        struct lar_listen *next;
        
        int             listen_fd;
	u_int8_t	allmulti;

        u_int8_t        igivname;
        u_int8_t        ifname[IFNAMSIZ];
        u_int8_t        ifmac[ETH_ALEN];
        u_int32_t       ifindex;
};

struct lar_client {
        struct lar_client *next;

        int                     client_fd;
        struct sockaddr_un     	client_addr;
};

struct lar_statistics {
        int debug;              
        
        /* event statistics... */
        unsigned long director_events;          /* total/all events */
        unsigned long director_errors;          /* general errors */
        
         /* fd statistics... */
        unsigned long open_fds;
        unsigned long wmark_fd;
        unsigned long highest_fd;
};

#ifdef NOT
struct sna_lar_dinfo {
        struct sna_lar_dinfo    *next;
        struct sna_lar_dinfo    *prev;

        u_int8_t                    ldev;   /* local interface */
        struct sna_netid        netid;
        struct sna_lar_snpa     snpa;
        u_int8_t                    group[SNA_RESOURCE_NAME_LEN];
        u_int32_t                   rtcap;
};
#endif

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
