/* lar_unix.c: generic unix functions to access the lar daemon.
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
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* required for llc sockets. */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/llc.h>

/* out stuff. */
#include "lar.h"
#include "lar_list.h"
#include "lard_load.h"
#include "lard.h"
#include "lar_unix.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif

int lar_unix_cnt_snpa(struct larattr *la, void *data, int *cnt)
{
	if (la->lara_type == LARA_SNPA)
		(*cnt)++;
	return 0;
}

int lar_unix_cnt_member(struct larattr *la, void *data, int *cnt)
{
	if (la->lara_type == LARA_MEMBER)
		(*cnt)++;
	return 0;
}

int lar_unix_xtract_snpa(struct larattr *la, void *data, lar_snpa_t **snpa, int *cnt)
{
	if (la->lara_type == LARA_SNPA) {
		snpa[*cnt] = calloc(1, sizeof(lar_snpa_t));
		memcpy(snpa[*cnt], data, sizeof(lar_snpa_t));
		(*cnt)++;
	}
	return 0;
}

int lar_unix_xtract_member(struct larattr *la, void *data, lar_member_t **members, int *cnt)
{
	if (la->lara_type == LARA_MEMBER) {
		members[*cnt] = calloc(1, sizeof(lar_member_t));
		memcpy(members[*cnt], data, sizeof(lar_member_t));
		(*cnt)++;
	}
	return 0;
}

int lar_unix_xtract_errno(struct larattr *la, void *data, int *err)
{
	if(la->lara_type == LARA_ERR)
		memcpy(err, data, sizeof(int));
	return 0;
}

int lar_unix_rx_record(struct larattr *la, void *data, lar_record_usr_t *recd)
{
	int i;
 
        if (!recd)
                return EINVAL;
        switch (la->lara_type) {
                case LARA_RTCAP:
                        memcpy(&recd->rtcap, data, sizeof(lar_rtcap_t));
                        break;
                        
                case LARA_NETID:
                        memcpy(recd->netid, data, sizeof(lar_netid_t));
                        break;

                case LARA_NAME:
                        memcpy(recd->name, data, sizeof(lar_name_t));
                        break;

                case LARA_GROUP:
                        for(i = 0; recd->groups[i] != NULL; i++);
                        recd->groups[i] = new_s(sizeof(lar_group_t));
                        memcpy(recd->groups[i], data, sizeof(lar_group_t));
			recd->groups[i + 1] = NULL;
                        break;

                case (LARA_SNPA):
			for(i = 0; recd->snpas[i] != NULL; i++);
                        recd->snpas[i] = new_s(sizeof(lar_snpa_t));
                        memcpy(recd->snpas[i], data, sizeof(lar_snpa_t));
                        recd->snpas[i + 1] = NULL;
                        break;

                default:
                        printf("Unknown %d of len %d\n", la->lara_type, la->lara_len);
        }
        return 0;
}

int lar_unix_rx_erase(struct larattr *la, void *data, lar_erase_usr_t *erase)
{
        if (!erase)
                return EINVAL;
        switch (la->lara_type) {
                case LARA_NETID:
                        memcpy(erase->netid, data, sizeof(lar_netid_t));
                        break;
                
                case LARA_NAME:
                        memcpy(erase->name, data, sizeof(lar_name_t));
                        break;

                default:
                        printf("Unknown %d of len %d\n", la->lara_type, la->lara_len);
        }
        return 0;
}

int lar_unix_rx_search(struct larattr *la, void *data, lar_search_usr_t *srch)
{
        if (!srch)
                return -EINVAL;
        switch (la->lara_type) {
                case LARA_NETID:
                        memcpy(srch->netid, data, LARA_PAYLOAD(la));
                        break;

                case LARA_GROUP:
                        memcpy(srch->group, data, LARA_PAYLOAD(la));
                        break;

                case LARA_RTCAP:
                        memcpy(&srch->rtcap, data, LARA_PAYLOAD(la));
                        break;

                default:
                        printf("build_search invalid attr %d\n", la->lara_type);
                        break;
        }
        return 0;
}

int lar_unix_rx_find(struct larattr *la, void *data, lar_find_usr_t *find)
{               
        if (!find)
                return -EINVAL;
        switch (la->lara_type) {
                case LARA_NETID:
                        memcpy(find->netid, data, LARA_PAYLOAD(la));
                        break;

                case LARA_NAME:
                        memcpy(find->name, data, LARA_PAYLOAD(la));
                        break;
                
                default:
                        printf("build_find invalid attr %d\n", la->lara_type);
                        break;
        }
        return 0;
}

struct larmsg *larmsg_put(int type, int len)
{
        struct larmsg *lh;

        lh = (struct larmsg *)calloc(1, len);
        lh->type        = type;
        lh->len         = len;
        return (lh);
}

struct larmsg *lara_put(struct larmsg *lh, int attrtype, int attrlen, const void *attrdata)
{
        struct larattr *lara;
        int size = LARA_LENGTH(attrlen);

	lh = realloc(lh, lh->len + LARA_ALIGN(size));
	lara = LARMSG_NDATA(lh);
        lara->lara_type = attrtype;
        lara->lara_len  = size;
        memcpy(LARA_DATA(lara), attrdata, attrlen);
        lh->len += LARA_ALIGN(size);
	return (lh);
}

int lar_unix_init(void)
{
	struct sockaddr_un un;
        int fd, err;

        fd = socket(PF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
                return fd;
        memset(&un, 0, sizeof(struct sockaddr_un));
        un.sun_family = AF_UNIX;
	memcpy(&un.sun_path[1], _PATH_LAR_UDS, strlen(_PATH_LAR_UDS));
	err = connect(fd, (struct sockaddr *)&un, sizeof(un));
	if (err < 0) {
		close(fd);
		return err;
	}
	return fd;
}

int lar_unix_fini(int sk)
{
	return close(sk);
}

int lar_unix_send(int skfd, void *data, int len)
{
	return send(skfd, data, len, 0);
}

int lar_unix_recv(int skfd, void *data, int len)
{
        return recv(skfd, data, len, 0);
}

int lar_unix_send_errno(int skfd, int32_t err)
{
        struct larmsg *lh;
	int rc;
        lh = larmsg_put(LAR_OP_ERRNO, sizeof(*lh));
        lh = lara_put(lh, LARA_ERR, sizeof(err), &err);
	rc = lar_unix_send(skfd, lh, lh->len);
	free(lh);
	return rc;
}
