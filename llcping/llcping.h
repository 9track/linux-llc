/* llcping.h: main header file.
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

#ifndef _LLCPING_H
#define _LLCPING_H

#define LLC_DEFAULT_LEN		64
#define LLC_DEFAULT_INTERVAL	1
#define LLC_DEFAULT_SSAP	0x00
#define LLC_DEFAULT_DSAP	0x00

#define LLC_MIN_LEN		(3 + 8)
#define LLC_MAX_LEN		(65535 - 3)
#define LLC_MAX_INTERVAL	10

#define new(p)          ((p) = calloc(1, sizeof(*(p))))
#define new_s(s)        calloc(1, s)

#define LLC_TYPE_NULL		0
#define LLC_TYPE_1		1
#define LLC_TYPE_2		2

struct llc_options {
	u_int8_t type;
	u_int8_t flip;
	u_int8_t quiet;
	u_int8_t flood;
	u_int8_t hexdump;
	u_int8_t numeric;
	u_int8_t fill;
	u_int8_t test;
	u_int8_t ua;

	u_int8_t options;
	u_int32_t retry;
	u_int32_t size;
	u_int32_t ack;
	u_int32_t p;
	u_int32_t reject;
	u_int32_t busy;
	u_int32_t txwin;
	u_int32_t rxwin;

	u_int32_t len;
	u_int32_t wait;

	u_int32_t count;		/* number of packets to tx. */
	u_int32_t received;		/* number of packets rx'd. */
	u_int32_t repeats;		/* numbre of duplicates. */
	u_int32_t transmitted;		/* outbound sequence number. */

	u_int8_t ssap;
	u_int8_t smac[IFHWADDRLEN];

        u_int8_t dsap;
	u_int8_t dmac[IFHWADDRLEN];

	u_int8_t is_root;

	time_t last_time;
	u_int8_t timing;
	u_int32_t tmin;
	u_int32_t tmax;
	u_int32_t tsum;

	int sk;
	struct sockaddr_llc dst;
	char outpacket[LLC_MAX_LEN];
};

#endif	/* _LLCPING_H */
