/* dlswd.h: dlsw header file.
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

#ifndef _DLSWD_H
#define _DLSWD_H

#define _PATH_DLSWD_XML_HREF  	"http://www.linux-sna.org/dlsw"
#define _PATH_DLSWDCONF       	"/etc/dlswd.xml"
#define _PATH_DLSWDPID        	"/var/run/dlswd.pid"
#define _PATH_DLSWDLIB        	"/usr/lib/dlswd"
#define _PATH_PROC_NET_DEV      "/proc/net/dev"
#define _PATH_DLSW_USER_TABLE	"/var/run/dlsw_partners"

#define DLSW_PARTNER_CONNECT_TIMEOUT	10
#define DLSW_DIR_TIMEOUT		50000

#define new(p)		((p) = calloc(1, sizeof(*(p))))
#define new_s(s)	calloc(1, s)

typedef struct {
	struct list_head list;

	u_int8_t state;
} dlsw_circuit_t;

#define DLSW_PARTNER_LOCAL	0x01
#define DLSW_PARTNER_STATIC	0x02
#define DLSW_PARTNER_DYNAMIC	0x04
#define DLSW_PARTNER_ACTIVE	0x08
#define DLSW_PARTNER_INACTIVE	0x10
#define DLSW_PARTNER_INBOUND	0x20
#define DLSW_PARTNER_OUTBOUND	0x40

typedef struct {
	struct list_head list;

	/* stored data. */
	struct in_addr 		ip;
	u_int16_t 		read_port;
	u_int16_t 		write_port;
	dlsw_version_t 		version;
	dlsw_vstring_t		version_string;
	dlsw_oui_t		vendor_id;
	dlsw_oui_t		vendor_context;
	dlsw_tcp_conn_t		tcp_conn;
	dlsw_pace_win_t		pacing_window;
	
	/* run-time data. */
	int 			read_fd;
        int 			write_fd;
	u_int32_t 		flags;
	u_int8_t 		status;
	dlsw_cap_cmd_pkt_t 	*saved_capXchng;
	struct list_head 	circuit_list;
	struct list_head 	lhw_mac_list;
} dlsw_partner_t;

struct dlsw_listen {
        struct list_head list;

        int                     listen_fd;
        struct sockaddr_llc     laddr;

        u_int8_t                ifname[IFNAMSIZ];
        u_int8_t                ifmac[ETH_ALEN];
        u_int32_t               ifindex;

	u_int8_t		sna;
	u_int8_t		netbios;
	u_int8_t		**sna_sap_list;
	u_int8_t		**netbios_sap_list;
	u_int8_t		mac_addr_exclusive;
	u_int8_t		netbios_exclusive;
	dlsw_mac_addr_t		**user_mac_addr_list;
	dlsw_netbios_name_t	**user_netbios_name_list;
};

/* general dlsw daemon statistics */
struct dlsw_statistics {
	int suspend;
	int debug;

	dlsw_vstring_t	version_string;
	dlsw_oui_t	vendor_id;
	dlsw_oui_t	vendor_context;
	
        unsigned long monitor_tx_bytes;
        unsigned long monitor_tx_errors;
        unsigned long monitor_tx_drops; 
        unsigned long monitor_rx_bytes;
        unsigned long monitor_rx_errors;
        unsigned long monitor_rx_drops;

	/* fd statistics... */
	unsigned long open_fds;
	unsigned long wmark_fd;
	unsigned long highest_fd;

	unsigned long director_events;          /* total/all events */
        unsigned long director_errors;          /* general errors */
        unsigned long monitor_events;
        unsigned long monitor_errors;
        unsigned long suspend_events_tossed;
};

extern char *dlsw_print_sap_bitmap(u_int8_t *sl);

extern int map_word(struct wordmap *wm, const char *word);
#endif	/* DLSWD_H */
