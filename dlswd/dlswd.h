/* dlswd.h: dlsw header file.
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

#ifndef _DLSWD_H
#define _DLSWD_H

#define _PATH_DLSWD_XML_HREF  	"http://www.linux-sna.org/dlsw"
#define _PATH_DLSWDCONF       "/etc/dlswd.xml"
#define _PATH_DLSWDPID        "/var/run/dlswd.pid"
#define _PATH_DLSWDLIB        "/usr/lib/dlswd"
#define _PATH_PROC_NET_DEV      "/proc/net/dev"

#define new(p)		((p) = calloc(1, sizeof(*(p))))
#define new_s(s)	calloc(1, s)

struct mon_clt {
        struct mon_clt *next;
	struct sockaddr_in ipaddr;
        int trace_npc;
        int fd;
};

/* general dlsw daemon statistics */
struct dlsw_statistics {
	int suspend;
	int debug;

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

extern struct mon_clt *dlsw_find_monitor_by_fd(int fd);
extern int dlsw_delete_monitor_list(void);
extern int dlsw_monitor_delete(int fd);

extern char **makeargv(char *line, int *pargc, char **parg);
extern int map_word(struct wordmap *wm, const char *word);
#endif	/* DLSWD_H */
