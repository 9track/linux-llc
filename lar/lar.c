/* lar.c: generic functions to perform lan address resolution.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* required for llc sockets. */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/llc.h>

/* out stuff. */
#include "lar.h"
#include "lar_unix.h"

/* Function: lar_find_member
 * Description:
 *  higher layer request CCE to determine the name of one (or more) member
 *  of the specified group with the specified routing capabilities and netid,
 *  and optionally, the SNPA of one such member.
 *
 * Parameters:
 *
 * Returns:
 *  0 and MEMBER, upon success.
 *  Negative and NULL, upon failure with errno set.
 */
lar_member_t **lar_find_member(const u_int8_t fflag, const u_int8_t *netid, 
	const u_int8_t *group, const u_int32_t rtmask, int32_t *rc)
{
        char buf[LAR_MAX_I_LEN];
	lar_member_t **members;
        int lfd, len, err = 0;
        int i, member_cnt;
	struct larmsg *lh;

        /* connect to server. */ 
        lfd = lar_unix_init();
        if (lfd < 0) {
		err = ENOTCONN;
		goto out;
	}
        
        /* build and send record. */
        lh = larmsg_put(LAR_OP_FIND_MEMBER, sizeof(*lh));
	lh = lara_put(lh, LARA_NETID, strlen(netid), netid); 
	lh = lara_put(lh, LARA_GROUP, strlen(group), group);
        lh = lara_put(lh, LARA_RTCAP, sizeof(rtmask), &rtmask);
        err = lar_unix_send(lfd, lh, lh->len);
        if (err < 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
		free(lh);
		goto out;
        }
	free(lh);

	/* get response. */
	len = sizeof(buf);
        err = lar_unix_recv(lfd, buf, len);
        if (err < 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
                goto out;
        }

        err = -EINVAL;
        lh = (struct larmsg *)buf;
        lar_attr_parse(lh, lar_unix_xtract_errno, &err);
        if (err != 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
                goto out;
        }

        member_cnt = i = 0;
        lar_attr_parse(lh, lar_unix_cnt_member, &member_cnt);
        members = calloc(1, sizeof(lar_member_t) * (member_cnt + 1));
        lar_attr_parse(lh, lar_unix_xtract_member, members, &i);
        members[member_cnt] = NULL;
        lar_unix_fini(lfd);
out:    errno = err;
        *rc   = -err;
        return members;
}

/* Function: lar_find
 * Description:
 *  higher layer requests CCE to determine SNPA of a network entity with the
 *  specified netid and name.
 *
 * Parameters:
 *
 * Returns:
 *  0 and SNPA, upon success.
 *  Negative and NULL, upon failure with errno set.
 */
lar_snpa_t **lar_find(const u_int8_t *netid, const u_int8_t *name, int32_t *rc)
{
	char buf[LAR_MAX_I_LEN];
        int lfd, len, err = 0;
	int snpa_cnt = 0, i;
	lar_snpa_t **snpa;
        struct larmsg *lh;

        /* connect to server. */ 
        lfd = lar_unix_init();
        if (lfd < 0) {
		err = ENOTCONN;
		goto out;
	}
        
        /* build and send record. */
        lh = larmsg_put(LAR_OP_FIND, sizeof(*lh));
	lh = lara_put(lh, LARA_NETID, strlen(netid), netid);
        lh = lara_put(lh, LARA_NAME, strlen(name), name);
        err = lar_unix_send(lfd, lh, lh->len);
        if (err < 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
		free(lh);
		goto out;
        }
	free(lh); 

	/* get response. */
	len = sizeof(buf);
        err = lar_unix_recv(lfd, buf, len);
        if (err < 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
                goto out;
        }

	err = EINVAL;
        lh = (struct larmsg *)buf;
        lar_attr_parse(lh, lar_unix_xtract_errno, &err);
        if (err != 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
                goto out; 
        }

	snpa_cnt = i = 0;
        lar_attr_parse(lh, lar_unix_cnt_snpa, &snpa_cnt);
        snpa = calloc(1, sizeof(lar_snpa_t) * (snpa_cnt + 1));
	lar_attr_parse(lh, lar_unix_xtract_snpa, snpa, &i);
	snpa[snpa_cnt] = NULL;
        lar_unix_fini(lfd);
out:	errno = err;
	*rc   = -err;
	return snpa;
}

/* Function: lar_search
 * Description:
 *  higher layer requests CCE to determine all network entities that are members
 *  of the specified group and that have the specified routing capabilites and
 *  netid.
 *
 * Parameters:
 *
 * Returns:
 *  0 and MEMBERS, upon success.
 *  Negative and NULL, upon failure with errno set.
 */
lar_member_t **lar_search(const u_int8_t *netid, const u_int8_t *group, 
	const u_int32_t rtcap, int32_t *rc)
{
	char buf[LAR_MAX_I_LEN];
	lar_member_t **members;
        int lfd, len, err = 0;
	struct larmsg *lh; 
	int i, member_cnt;

        /* connect to server. */ 
        lfd = lar_unix_init();
        if (lfd < 0) {
		err = ENOTCONN;
		goto out;
	}
        
        /* build and send record. */
        lh = larmsg_put(LAR_OP_SEARCH, sizeof(*lh));
	lh = lara_put(lh, LARA_NETID, strlen(netid), netid);
	lh = lara_put(lh, LARA_GROUP, strlen(group), group);
        lh = lara_put(lh, LARA_RTCAP, sizeof(rtcap), &rtcap);
        err = lar_unix_send(lfd, lh, lh->len);
        if (err < 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
		free(lh);
		goto out;
        }
	free(lh);

 	/* get response. */
	len = sizeof(buf);
        err = lar_unix_recv(lfd, buf, len);
        if (err < 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
                goto out;
        }

        err = EINVAL;
        lh = (struct larmsg *)buf;
	lar_attr_parse(lh, lar_unix_xtract_errno, &err);
	if (err != 0) {
		lar_unix_fini(lfd);
		goto out;
	}

	member_cnt = i = 0;
	lar_attr_parse(lh, lar_unix_cnt_member, &member_cnt);
	members = calloc(1, sizeof(lar_member_t) * (member_cnt + 1));
	lar_attr_parse(lh, lar_unix_xtract_member, members, &i);
	members[member_cnt] = NULL;
        lar_unix_fini(lfd);
out:	errno = err;
	*rc   = -err;
	return members;
}

/* Function: lar_record
 * Description:
 *  higher layer requests CCE to record a resource identified by 'netid.name'
 *  as available, addressable through each of the list of SNPAs, having the
 *  specified routing capabilities, belonging to each of the list of group
 *  names and to the specified connection network.
 *
 * Parameters:
 *
 * Returns:
 *  0, upon success.
 *  Negative upon failure with errno set.
 */
int32_t lar_record(const u_int8_t *netid, const u_int8_t *name, 
	const u_int32_t rtcap, lar_snpa_t **snpa_list, u_int8_t **groups)
{
	char buf[LAR_MAX_I_LEN];
	int lfd, len, err = 0;
	struct larmsg *lh;

	/* connect to server. */
	lfd = lar_unix_init();
        if (lfd < 0) {
		err = ENOTCONN;
		goto out;
	}

	/* build and send record. */
	lh = larmsg_put(LAR_OP_RECORD, sizeof(*lh));
	lh = lara_put(lh, LARA_NETID, strlen(netid), netid);
	lh = lara_put(lh, LARA_NAME, strlen(name), name);
	lh = lara_put(lh, LARA_RTCAP, sizeof(rtcap), &rtcap);
	while (*groups != NULL) {
		lh = lara_put(lh, LARA_GROUP, strlen(*groups), *groups);
		groups++;
	}
	while (*snpa_list != NULL) {
		lh = lara_put(lh, LARA_SNPA, sizeof(lar_snpa_t), *snpa_list);
		snpa_list++;
	}
	err = lar_unix_send(lfd, lh, lh->len);
	if (err < 0) {
		err = EAGAIN;
		lar_unix_fini(lfd);
		free(lh);
		goto out;
	}
	free(lh);

	/* get response. */
	len = sizeof(buf);
	err = lar_unix_recv(lfd, buf, len);
	if (err < 0) {
		err = EAGAIN;
		lar_unix_fini(lfd);
		goto out;
	}

	err = EINVAL; 
        lh = (struct larmsg *)buf;
        lar_attr_parse(lh, lar_unix_xtract_errno, &err);
	lar_unix_fini(lfd);
out:	errno = err;
	err   = -err;
	return err;
}

/* Function: lar_erase
 * Description:
 *  higher layer requests CCE to remove the resource identified by 'netid.name'
 *  from the list of network entries recorded at this station.
 *
 * Parameters:
 *
 * Returns:
 * 0, upon success.
 * Negative upon failure with errno set.
 */
int32_t lar_erase(const u_int8_t *netid, const u_int8_t *name)
{
	char buf[LAR_MAX_I_LEN];
        int lfd, len, err = 0;
	struct larmsg *lh;

        /* connect to server. */
        lfd = lar_unix_init();
        if (lfd < 0) {
		err = ENOTCONN;
		goto out;
	}

        /* build and send record. */
        lh = larmsg_put(LAR_OP_ERASE, sizeof(*lh));
        lh = lara_put(lh, LARA_NETID, strlen(netid), netid);
        lh = lara_put(lh, LARA_NAME, strlen(name), name);
        err = lar_unix_send(lfd, lh, lh->len);
        if (err < 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
		free(lh);
		goto out;
        }
	free(lh);

	/* get response. */        
        len = sizeof(buf);
        err = lar_unix_recv(lfd, buf, len);
        if (err < 0) {
		err = EAGAIN;
                lar_unix_fini(lfd);
		goto out;
        }
 
	err = EINVAL;
        lh = (struct larmsg *)buf;
        lar_attr_parse(lh, lar_unix_xtract_errno, &err);
        lar_unix_fini(lfd);
out:	errno = err;
	err   = -err;
	return err;
}
