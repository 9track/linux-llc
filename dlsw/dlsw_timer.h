/* dlsw_timer.h: Data link switching timer defintions.
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

#ifndef _DLSW_TIMER_H
#define _DLSW_TIMER_H

typedef void (*timerproc_t)(void *data);

extern void *timer_start(short one_shot, unsigned long value, 
	timerproc_t proc, void *data);
extern int timer_stop(void *timer);

#endif /* _DLSW_TIMER_H */
