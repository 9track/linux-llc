/* lar_unix.c: generic unix functions to access the lar daemon.
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
#include "lar_unix.h"
#include "lard.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX    108
#endif

static char *pr_ether(char *ptr)
{
        static char buff[64];

        snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X",
        	(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
                (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
        return(buff);
}

int lar_attr_print(struct larattr *la, void *data)
{
        printf("type: %d len: %d\n", la->lara_type, la->lara_len);
                        
        switch(la->lara_type) {
                case (LARA_CORRELATOR): {
                        lar_correlator_t *c = LARA_DATA(la);
                        printf("correlator: %d\n", *c);
                        break;
                }

                case (LARA_RTCAP): {
                        lar_rtcap_t *r = LARA_DATA(la);
                        printf("rtcap: %d\n", *r);
                        break;
                }

                case (LARA_MAC): {
                        lar_mac_t *m = LARA_DATA(la);
                        printf("mac: %s\n", pr_ether((char *)m));
                        break;
                }

                case (LARA_LSAP): {
                        lar_lsap_t *l = LARA_DATA(la);
                        printf("lsap: 0x%02X\n", *l);
                        break;
                }

                case (LARA_NETID): {
                        lar_netid_t *n = LARA_DATA(la);
                        printf("netid: %s\n", (char *)n);
                        break;
                }

                case (LARA_NAME): {
                        lar_name_t *n = LARA_DATA(la);
                        printf("name: %s\n", (char *)n);
                        break;
                }

                case (LARA_GROUP): {
                        lar_group_t *g = LARA_DATA(la);
                        printf("group: %s\n", (char *)g);
                        break;
                }

                case (LARA_SNPA): {
                        lar_snpa_t *s = LARA_DATA(la);
                        printf("snpa: %s@0x%02X\n", pr_ether(s->mac), s->lsap);
                        break;
                }

                case (LARA_SOLICIT):
                default:
                        printf("Unknown %d of len %d\n", la->lara_type, la->lara_len);
        }

	return (0);
}

struct larmsg *larmsg_put(int type, int seq, int len)
{
        struct larmsg *lh;

        lh = (struct larmsg *)calloc(1, len);
        lh->type        = type;
        lh->len         = len;
        lh->seq         = seq;
        return (lh);
}

void lara_put(struct larmsg *lh, int attrtype, int attrlen, const void *attrdata)
{
        struct larattr *lara;
        int size = LARA_LENGTH(attrlen);

	lh = realloc(lh, lh->len + LARA_ALIGN(size));
	lara = LARMSG_NDATA(lh);
        lara->lara_type = attrtype;
        lara->lara_len  = size;
        memcpy(LARA_DATA(lara), attrdata, attrlen);
        lh->len += LARA_ALIGN(size);
}

int lar_unix_init(void)
{
	struct sockaddr_un un;
        int fd, err;

        fd = socket(PF_UNIX, SOCK_STREAM, 0);
        if(fd < 0)
                return (fd);

        memset(&un, 0, sizeof(struct sockaddr_un));
        un.sun_family = AF_UNIX;
	memcpy(&un.sun_path[1], _PATH_LAR_UDS, strlen(_PATH_LAR_UDS));
	err = connect(fd, (struct sockaddr *)&un, sizeof(un));
	if(err < 0) {
		close(fd);
		return (err);
	}

	return (fd);
}

int lar_unix_fini(int sk)
{
	return (close(sk));
}

int lar_unix_send(int skfd, void *data, int len)
{
	return (send(skfd, data, len, 0));
}

int lar_unix_recv(int skfd, void *data, int *len)
{
        return (recv(skfd, data, *len, 0));
}
