/* dlsw_load.h: loader header file.
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

#ifndef _DLSW_LOAD_H
#define _DLSW_LOAD_H

#define next_arg(X)     (*X = *X + 1)

struct wordmap {
        const char *word;
        int val;
};

struct monitor {
	struct monitor *next;
	unsigned short port;
};

/* This structure describes global (ie., server-wide) parameters.
 */
typedef struct {
        int debug_level;

	struct monitor *m;
} global;

extern int load_config_file(char *cfile);
extern int load_config(global *ginfo);
extern int dlsw_load_monitor(struct monitor *m);
#endif	/* _DLSW_LOAD_H */
