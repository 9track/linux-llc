/* dlswmonitor.h: header file.
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

#ifndef _DLSWMONITOR_H
#define _DLSWMONITOR_H

enum commands {
	SYSTEM = 1,		/* display linux system information. */
	STATUS,			/* display dlswd status. */
	NETWORK,		/* display network interface stats. */
	DEBUG,
	SUSPEND,
        RESUME
};

struct dlm_result {
	unsigned char error;	/* standard error numbers. errno.h */
};

struct dlm_cmd {
	unsigned char cmd;
	int size;
	unsigned char data[0];	/* any command data start here. */
};

struct dlm_entries {
	int num;		/* total number data entries. */
	int size;		/* total data size. */
	int ssize;		/* size of single data entry. */
	unsigned char data[0];	/* start of data entries. */
};

struct dlm_debug {
	int level;
};

struct dlm_trace {
	int toggle;
};

struct dlm_loop {
	int toggle;
};

struct dlm_iface {
	char name[17];
	unsigned long rx_bytes;
	unsigned long rx_packets;
	unsigned long rx_errs;
	unsigned long rx_drop;
	unsigned long rx_fifo;
	unsigned long rx_frame;
	unsigned long rx_compressed;
	unsigned long rx_multicast;

	unsigned long tx_bytes;
	unsigned long tx_packets;
	unsigned long tx_errs;
	unsigned long tx_drop;
	unsigned long tx_fifo;
	unsigned long tx_colls;
	unsigned long tx_carrier;
	unsigned long tx_compressed;	
};

struct dlm_status {
	proc_t dl_proc;
	struct dlsw_statistics statistics;
};

struct dlm_system {
	struct utsname name;
	int num_users;

	unsigned long num_process;
        unsigned long run_process;

	unsigned long long mem_total;
	unsigned long long mem_used;
	unsigned long long mem_free;
	unsigned long long mem_shared;
	unsigned long long mem_buffers;
	unsigned long long mem_cached;

	double uptime_secs;
	double idle_secs;
	double load_avg_1;
	double load_avg_5;
	double load_avg_15;
};

#endif	/* _DLSWMONITOR_H */
