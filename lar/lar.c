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
#include "lar_unix.h"
#include "lar.h"

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
int lar_find_member(const u_int8_t fflag, const u_int8_t *netid, 
	const u_int8_t *group, const u_int32_t rtmask, lar_search_t *member)
{
        struct larmsg *lh;
	char buf[128];
        int lfd, len, err = 0;

        /* connect to server. */ 
        lfd = lar_unix_init();
        if(lfd < 0) {
		err = lfd;
		goto out;
	}
        
        /* build record. */
        lh = larmsg_put(LAR_UNIX_FIND_MEMBER, 1, sizeof(*lh));
	lara_put(lh, LARA_NETID, strlen(netid), netid); 
	lara_put(lh, LARA_GROUP, strlen(group), group);
        lara_put(lh, LARA_RTCAP, sizeof(rtmask), &rtmask);

        /* send to lard. */
        err = lar_unix_send(lfd, lh, lh->len);
        if(err < 0) {
                lar_unix_fini(lfd);
		free(lh);
		goto out;
        }
	free(lh);

	/* get response. */
	len = sizeof(buf);
        err = lar_unix_recv(lfd, buf, &len);
        if(err < 0) {
                lar_unix_fini(lfd);
                goto out;
        }

        err = -EINVAL;
        lh = (struct larmsg *)buf;
        if(lh->type == LAR_UNIX_ERRNO && lh->seq == 2) {
                struct larattr *la = LARMSG_DATA(lh);
                int llen = LARMSG_PAYLOAD(lh, 0);
                if(LARA_OK(la, llen))
                        err = *((int *)LARA_DATA(la));
        }
	errno = err;
        err = -err;
 
        lar_unix_fini(lfd);
out:	return (err);
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
int lar_find(const u_int8_t *netid, const u_int8_t *name, lar_snpa_t *snpa)
{
        struct larmsg *lh;
	char buf[128];
        int lfd, len, err = 0;

        /* connect to server. */ 
        lfd = lar_unix_init();
        if(lfd < 0) {
		err = lfd;
		goto out;
	}
        
        /* build record. */
        lh = larmsg_put(LAR_UNIX_FIND, 1, sizeof(*lh));
	lara_put(lh, LARA_NETID, strlen(netid), netid);
        lara_put(lh, LARA_NAME, strlen(name), name);
        
        /* send to lard. */
        err = lar_unix_send(lfd, lh, lh->len);
        if(err < 0) {
                lar_unix_fini(lfd);
		free(lh);
		goto out;
        }
	free(lh); 

	/* get response. */
	len = sizeof(buf);
        err = lar_unix_recv(lfd, buf, &len);
        if(err < 0) {
                lar_unix_fini(lfd);
                goto out;
        }

        err = -EINVAL;
        lh = (struct larmsg *)buf;
        if(lh->type == LAR_UNIX_ERRNO && lh->seq == 2) {
                struct larattr *la = LARMSG_DATA(lh);
                int llen = LARMSG_PAYLOAD(lh, 0);
                if(LARA_OK(la, llen))
                        err = *((int *)LARA_DATA(la));
        }
	errno = err;
        err = -err;

        lar_unix_fini(lfd);
out:	return (err);
}

/* Fuunction: lar_search
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
int lar_search(const u_int8_t *netid, const u_int8_t *group, 
	const u_int32_t rtcap, lar_member_t *members)
{
        struct larmsg *lh;
	char buf[128];
        int lfd, len, err = 0;

        /* connect to server. */ 
        lfd = lar_unix_init();
        if(lfd < 0) {
		err = lfd;
		goto out;
	}
        
        /* build record. */
        lh = larmsg_put(LAR_UNIX_SEARCH, 1, sizeof(*lh));
	lara_put(lh, LARA_NETID, strlen(netid), netid);
	lara_put(lh, LARA_GROUP, strlen(group), group);
        lara_put(lh, LARA_RTCAP, sizeof(rtcap), &rtcap);
 
        /* send to lard. */
        err = lar_unix_send(lfd, lh, lh->len);
        if(err < 0) {
                lar_unix_fini(lfd);
		free(lh);
		goto out;
        }
	free(lh);

 	/* get response. */
	len = sizeof(buf);
        err = lar_unix_recv(lfd, buf, &len);
        if(err < 0) {
                lar_unix_fini(lfd);
                goto out;
        }

        err = -EINVAL;
        lh = (struct larmsg *)buf;
        if(lh->type == LAR_UNIX_ERRNO && lh->seq == 2) {
                struct larattr *la = LARMSG_DATA(lh);
                int llen = LARMSG_PAYLOAD(lh, 0);
                if(LARA_OK(la, llen))
                        err = *((int *)LARA_DATA(la));
        }
	errno = err;
        err = -err;

        lar_unix_fini(lfd);
out:	return (err);
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
int lar_record(const u_int8_t *netid, const u_int8_t *name, 
	const u_int32_t rtcap, lar_snpa_t **snpa_list, u_int8_t **groups)
{
	struct larmsg *lh;
	char buf[128];
	int lfd, len, err = 0;

	/* connect to server. */
	lfd = lar_unix_init();
        if(lfd < 0) {
		err = lfd;
		goto out;
	}

	/* build record. */
	lh = larmsg_put(LAR_UNIX_RECORD, 1, sizeof(*lh));
	lara_put(lh, LARA_NETID, strlen(netid), netid);
	lara_put(lh, LARA_NAME, strlen(name), name);
	lara_put(lh, LARA_RTCAP, sizeof(rtcap), &rtcap);
	while(*groups != NULL) {
		lara_put(lh, LARA_GROUP, strlen(*groups), *groups);
		groups++;
	}
	while(*snpa_list != NULL) {
		lara_put(lh, LARA_SNPA, sizeof(lar_snpa_t), *snpa_list);
		snpa_list++;
	}

	/* send to lard. */
	err = lar_unix_send(lfd, lh, lh->len);
	if(err < 0) {
		lar_unix_fini(lfd);
		free(lh);
		goto out;
	}
	free(lh);

	/* get response. */
	len = sizeof(buf);
	err = lar_unix_recv(lfd, buf, &len);
	if(err < 0) {
		lar_unix_fini(lfd);
		goto out;
	}

	err = EINVAL;
	lh = (struct larmsg *)buf;
	if(lh->type == LAR_UNIX_ERRNO && lh->seq == 2) {
		struct larattr *la = LARMSG_DATA(lh);
	        int llen = LARMSG_PAYLOAD(lh, 0);
		if(LARA_OK(la, llen))
			err = *((int *)LARA_DATA(la));
	}
	errno = err;
	err = -err;

	lar_unix_fini(lfd);
out:	return (err);
}

/* Function: lar_erase
 * Description:
 *  higher layer requests CCE to remove the resource identified by 'netid.name'
 *  from the list of network entiries recorded at this station.
 *
 * Parameters:
 *
 * Returns:
 * 0, upon success.
 * Negative upon failure with errno set.
 */
int lar_erase(const u_int8_t *netid, const u_int8_t *name)
{
	struct larmsg *lh;
	char buf[128];
        int lfd, len, err = 0;

        /* connect to server. */
        lfd = lar_unix_init();
        if(lfd < 0) {
		err = lfd;
		goto out;
	}

        /* build record. */
        lh = larmsg_put(LAR_UNIX_ERASE, 1, sizeof(*lh));
        lara_put(lh, LARA_NETID, strlen(netid), netid);
        lara_put(lh, LARA_NAME, strlen(name), name);

        /* send to lard. */
        err = lar_unix_send(lfd, lh, lh->len);
        if(err < 0) {
                lar_unix_fini(lfd);
		free(lh);
		goto out;
        }
	free(lh);

	/* get response. */        
        len = sizeof(buf);
        err = lar_unix_recv(lfd, buf, &len);
        if(err < 0) {
                lar_unix_fini(lfd);
		goto out;
        }
                
        err = -EINVAL;
        lh = (struct larmsg *)buf;
        if(lh->type == LAR_UNIX_ERRNO && lh->seq == 2) {
                struct larattr *la = LARMSG_DATA(lh);
                int llen = LARMSG_PAYLOAD(lh, 0);
                if(LARA_OK(la, llen))
                        err = *((int *)LARA_DATA(la));
        }
	errno = err;
        err = -err;

        lar_unix_fini(lfd);
out:	return (err);
}
