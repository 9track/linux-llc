/* lard.c: lan address resolution daemon.
 * Copyright (c) 2001, Jay Schulist.
 *
 * Written by Jay Schulist <jschlst@samba.org>
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
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>

/* required for llc sockets. */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/llc.h>

/* our stuff. */
#include "lar.h"
#include "lar_list.h"
#include "lard.h"
#include "lard_load.h"
#include "lar_unix.h"

#ifndef AF_LLC
#define AF_LLC          22
#define PF_LLC          AF_LLC
#endif

static char lar_server_gmac[]  = {0x03, 0x00, 0x00, 0x00, 0x00, 0x02};
static char lar_nserver_gmac[] = {0x03, 0x00, 0x00, 0x80, 0x00, 0x00};
static char lar_all_cce_gmac[] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x20};

char version_s[]                        = VERSION;
char name_s[]                           = "lard";
char desc_s[]                           = "Lan address resolution daemon";
char maintainer_s[]                     = "Jay Schulist <jschlst@samba.org>";

int lar_ifr_fd = -1;
fd_set lar_all_fds;
int lar_unix_fd;

char config_file[300]                   = _PATH_LARDCONF;
global *lar_config_info                 = NULL;
struct lar_statistics *lar_stats	= NULL;
struct lar_listen *lar_listen_list	= NULL;
struct lar_client *lar_client_list	= NULL;
static list_head(lar_netent_list);

static sigset_t blockmask, emptymask;
static int blocked = 0;

extern void sig_block(void); 
extern void sig_unblock(void);

char *pr_ether(char *ptr)
{
        static char buff[64];

        snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X",
        	(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
                (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
        return(buff);
}


void lar_count_and_set_fds(int fd, fd_set *all_fds)
{
        lar_stats->open_fds++;
        if(lar_stats->open_fds > lar_stats->wmark_fd)
                lar_stats->wmark_fd = lar_stats->open_fds;
        FD_SET(fd, all_fds);
        if(fd > lar_stats->highest_fd)
                lar_stats->highest_fd = fd;
        return;
}
        
void lar_count_and_clear_fds(int fd, fd_set *all_fds)
{
        lar_stats->open_fds--;
        FD_CLR(fd, all_fds);
        return;
}

struct lar_client *lar_find_client_by_fd(int fd)
{
        struct lar_client *l;

        for(l = lar_client_list; l != NULL; l = l->next)
                if(l->client_fd == fd)
                        return (l);
        return (NULL);
}

int lar_delete_client_list(void)
{
        struct lar_client *ent1, **clients1;

        clients1 = &lar_client_list;
        while((ent1 = *clients1) != NULL) {
                *clients1 = ent1->next;
                free(ent1);
        }

        return (0);
}

int lar_delete_clnt(struct lar_client *clnt)
{
        struct lar_client *ent, **clients;

        clients = &lar_client_list;
        while((ent = *clients) != NULL ){
                if(clnt->client_fd == ent->client_fd) {
                        *clients = ent->next;
                        free(ent);
                        return (0);
                }
                clients = &ent->next;
        }

        return (-ENOENT);
}

struct lar_listen *lar_find_listener_by_fd(int fd)
{
        struct lar_listen *l;

        for(l = lar_listen_list; l != NULL; l = l->next)
                if(l->listen_fd == fd)
                        return (l);
        return (NULL);
}

int lar_delete_listen_list(void)
{      
        struct lar_listen *ent1, **clients1;

        clients1 = &lar_listen_list;
        while((ent1 = *clients1) != NULL) {
                *clients1 = ent1->next;
                free(ent1);
        }

        return (0);
}

int lar_delete_linfo_list(void)
{       
        struct lar_linfo *ent1, **clients1;
        
        clients1 = &lar_config_info->ll;
        while((ent1 = *clients1) != NULL) {
                *clients1 = ent1->next;
                free(ent1);
        }
        
        return (0);
}

struct lar_netent *lar_find_netent_by_match(struct lar_netent *ent)
{
	struct list_head *le;

	list_for_each(le, &lar_netent_list) {
		struct lar_netent *tmp;

		tmp = list_entry(le, struct lar_netent, list);
		if(!memcmp(&ent->netid, &tmp->netid, sizeof(lar_netid_t))
			&& !memcmp(&ent->name, &tmp->name, sizeof(lar_name_t))
			&& !memcmp(&ent->rtcap, &tmp->rtcap, sizeof(lar_rtcap_t)))
			return (tmp);
	}

	return (NULL);
}

int lar_delete_netent_by_netid(struct lar_netent *ent)
{
	struct list_head *le;
	struct lar_netent *tmp = NULL;

        list_for_each(le, &lar_netent_list) {
                tmp = list_entry(le, struct lar_netent, list);
                if(!memcmp(&ent->netid, &tmp->netid, sizeof(lar_netid_t))
                        && !memcmp(&ent->name, &tmp->name, sizeof(lar_name_t)))
                        break;;
        }            
	if(!tmp)
		return (-ENOENT);

	list_del((struct list_head *)tmp);
	return (0);
}

int lar_send_user_err(int fd, int seq, int32_t err)
{
	struct larmsg *lh;

	/* build record. */
        lh = larmsg_put(LAR_UNIX_ERRNO, seq, sizeof(*lh));
        lara_put(lh, LARA_ERR, sizeof(err), &err);
        return (send(fd, lh, lh->len, 0));
}

int lar_build_netent(struct larattr *la, void *data, struct lar_netent *ent)
{
	if(!ent)
		return (EINVAL);

	switch(la->lara_type) {
                case (LARA_CORRELATOR): {
                        lar_correlator_t *c = LARA_DATA(la);
                        printf("correlator: %d\n", *c);
                        break;
                }

                case (LARA_RTCAP): {
                        lar_rtcap_t *r = LARA_DATA(la);
			memcpy(&ent->rtcap, r, sizeof(lar_rtcap_t));
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
			memcpy(&ent->netid, n, sizeof(lar_netid_t));
                        break;
		}

                case (LARA_NAME): {
                        lar_name_t *n = LARA_DATA(la);
			memcpy(&ent->name, n, sizeof(lar_name_t));
                        break;
                }

                case (LARA_GROUP): {
                        lar_group_t *g = LARA_DATA(la);
			int i;

			for(i = 0; i < LAR_MAX_SV_GROUP_NAMES; i++) {
				if(ent->group_list[i] == NULL)
					break;
			}
			if(i == LAR_MAX_SV_GROUP_NAMES) {
				printf("exhausted maximum group entries (%d)\n", i);
				return (EUSERS);
			}

			ent->group_list[i] = new_s(sizeof(lar_group_t));
			memcpy(ent->group_list[i], g, sizeof(lar_group_t));
                        break;
                }

                case (LARA_SNPA): {
                        lar_snpa_t *s = LARA_DATA(la);
			int i;

                        for(i = 0; i < LAR_MAX_SV_GROUP_NAMES; i++) {
                                if(ent->snpa_list[i] == NULL)
                                        break;
                        }
                        if(i == LAR_MAX_SV_GROUP_NAMES) {
                                printf("exhausted maximum snpa entries (%d)\n", i);
                                return (EUSERS);
                        }

                        ent->snpa_list[i] = new_s(sizeof(lar_snpa_t));
                        memcpy(ent->snpa_list[i], s, sizeof(lar_snpa_t));
                        break;
                }

                case (LARA_SOLICIT):
                default:
                        printf("Unknown %d of len %d\n", la->lara_type, la->lara_len);
        }

	return (0);
}

int lar_process_unix_record(struct lar_client *clnt, struct larmsg *lh)
{
	struct lar_netent *netent, *tmp;
	int err = 0;

	/* allocate new entry. */
	if(!new(netent)) {
		err = ENOMEM;
		goto out_r;
	}

	/* fill the new entry. */
	err = lar_attr_parse(lh, lar_build_netent, netent);
	if(err < 0) {
		free(netent);
		goto out_r;
	}

	/* check for an entry clash. */
	tmp = lar_find_netent_by_match(netent);
	if(tmp) {
		err = EEXIST;
		free(netent);
		goto out_r;
	}

	/* append the entry to our list. */
	time(&netent->create);
	list_add_tail((struct list_head *)netent, &lar_netent_list);

        /* send response. */
out_r:	err = lar_send_user_err(clnt->client_fd, ++lh->seq, err);
        if(err < 0) {
                printf("%s: send to user failed `%s'.\n", name_s, strerror(errno));
                return (err);
        }

	return (0);
}

int lar_process_unix_erase(struct lar_client *clnt, struct larmsg *lh)
{
	struct lar_netent *netent;
        int err = 0;
        
        /* allocate delete entry. */
        if(!new(netent)) {
                err = ENOMEM;
                goto out_r;
        }       
        
        /* fill the delete entry. */
        err = lar_attr_parse(lh, lar_build_netent, netent);
        if(err < 0) {
                free(netent);
                goto out_r;
        }

	/* delete the entry. */
        err = lar_delete_netent_by_netid(netent);
        if(err < 0) {
                err = ENOENT;
                free(netent);
                goto out_r;
        }

        /* send response. */
out_r:  err = lar_send_user_err(clnt->client_fd, ++lh->seq, err);
        if(err < 0) {
                printf("%s: send to user failed `%s'.\n", name_s, strerror(errno));
                return (err);
        }

	return (0);
}

int lar_process_unix_search(struct lar_client *clnt, struct larmsg *lh)
{
	int err;

        /* send response. */
        err = lar_send_user_err(clnt->client_fd, ++lh->seq, EOPNOTSUPP);
        if(err < 0) {
                printf("%s: send to user failed `%s'.\n", name_s, strerror(err));
                return (err);
        }

	return (0);
}

int lar_process_unix_find(struct lar_client *clnt, struct larmsg *lh)
{
	int err;

        /* send response. */
        err = lar_send_user_err(clnt->client_fd, ++lh->seq, EOPNOTSUPP);
        if(err < 0) {
                printf("%s: send to user failed `%s'.\n", name_s, strerror(err));
                return (err);
        }

	return (0);
}

int lar_process_unix_find_member(struct lar_client *clnt, struct larmsg *lh)
{
	int err;

        /* send response. */
        err = lar_send_user_err(clnt->client_fd, ++lh->seq, EOPNOTSUPP);
        if(err < 0) {
                printf("%s: send to user failed `%s'.\n", name_s, strerror(err));
                return (err);
        }

	return (0);
}

int lar_process_user(struct lar_client *clnt)
{
	struct larmsg *lh;
	int blen, len;
	char buf[4196];

	blen = sizeof(buf);
        len = recv(clnt->client_fd, buf, blen, 0);
        if(len < 0 || len == 0)
        {
        	if(errno == EINTR)
			return (0);
		lar_count_and_clear_fds(clnt->client_fd, &lar_all_fds);
		close(clnt->client_fd);
                lar_delete_clnt(clnt);
                return (0);
        }

	/* process data. */
	lh = (struct larmsg *)buf;
	switch(lh->type) {
		case (LAR_UNIX_RECORD):
			lar_process_unix_record(clnt, lh);
			break;

		case (LAR_UNIX_ERASE):
			lar_process_unix_erase(clnt, lh);
			break;

		case (LAR_UNIX_SEARCH):
			lar_process_unix_search(clnt, lh);
			break;

		case (LAR_UNIX_FIND):
			lar_process_unix_find(clnt, lh);
			break;

		case (LAR_UNIX_FIND_MEMBER):
			lar_process_unix_find(clnt, lh);
			break;

		default:
			lar_send_user_err(clnt->client_fd, ++lh->seq, -EINVAL);
	}
	return (0);
}

int lar_process_unix_accept(int fd)
{
	struct sockaddr_un from;
	struct lar_client *clnt;
	int fromlen;
	int client_fd;

	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	client_fd = accept(fd, (struct sockaddr *)&from, &fromlen);
	if(client_fd < 0)
		return (client_fd);

	if(!new(clnt))
		return (-ENOMEM);
	clnt->client_fd = client_fd;
	memcpy(&clnt->client_addr, &from, sizeof(from));
	clnt->next = lar_client_list;
	lar_client_list = clnt;
	lar_count_and_set_fds(client_fd, &lar_all_fds);
	return (0);
}

int lar_rx_build_group_names(sub_vector_t *sv, void *data, lar_group_t **groups)
{
	lar_group_t *g = data;
        int i;
                        
        for(i = 0; i < LAR_MAX_SV_GROUP_NAMES; i++) {
		if(groups[i] == NULL)
			break;
	}
	if(i == LAR_MAX_SV_GROUP_NAMES) {
		printf("exhausted maximum group entries (%d)\n", i);
		return (-EUSERS);
	}

        groups[i] = new_s(sizeof(lar_group_t));
	if(!groups[i]) 
		return (-ENOMEM);

        memcpy(groups[i], g, sizeof(lar_group_t));
	return (0);
}

int lar_rx_build_solicit(sub_vector_t *sv, void *data, lar_solicit_t *sol)
{
	switch(sv->id) {
		case LAR_SV_TARGET_NETID:
			memcpy(sol->netid, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_GROUP_NAME:
			memcpy(sol->group, data, LAR_SV_PAYLOAD(sv));
			break;

		default:
			printf("solicit: unknown sub-vector 0x%02X\n", sv->id);
			break;
	}

	return (0);
}

int lar_rx_build_advertise(sub_vector_t *sv, void *data, lar_advertise_t *adv)
{
	switch(sv->id) {
		case (LAR_SV_RESOURCE_NETID):
			memcpy(adv->netid, data, LAR_SV_PAYLOAD(sv));
			break;

		case (LAR_SV_RESOURCE_NAME):
			memcpy(adv->name, data, LAR_SV_PAYLOAD(sv));
			break;

		case (LAR_SV_RESOURCE_LSAP):
			memcpy(&adv->lsap, data, LAR_SV_PAYLOAD(sv));
			break;

		case (LAR_SV_RESOURCE_MAC):
			memcpy(adv->mac, data, LAR_SV_PAYLOAD(sv));
			break;

		case (LAR_SV_RTCAP):
			memcpy(&adv->rtcap, data, LAR_SV_PAYLOAD(sv));
			break;

		case (LAR_SV_CONN_NETID):
			memcpy(adv->conn_netid, data, LAR_SV_PAYLOAD(sv));
			break;

		case (LAR_SV_GROUP_NAMES):
			lar_ssub_vector_parse(sv, lar_rx_build_group_names, adv->groups);
			break;

		case (LAR_SV_RETURN_CCE_MAC):
			memcpy(adv->cce_mac, data, LAR_SV_PAYLOAD(sv));
			break;

		default:
			printf("advertise: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }

	return (0);
}

int lar_rx_build_find(sub_vector_t *sv, void *data, lar_find_t *find)
{
	switch(sv->id) {
		case LAR_SV_CORRELATOR:
			memcpy(&find->correlator, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_TARGET_NETID:
			memcpy(find->tnetid, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_TARGET_NAME:
			memcpy(find->tname, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_ORIGIN_NETID:
			memcpy(find->onetid, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_ORIGIN_NAME:
			memcpy(find->oname, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_ORIGIN_LSAP:
			memcpy(&find->olsap, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_ORIGIN_MAC:
			memcpy(find->omac, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_ORIGIN_CCE_MAC:
			memcpy(find->cce_mac, data, LAR_SV_PAYLOAD(sv));
			break;

                default:
                        printf("find: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }

	return (0);
}

int lar_rx_build_found(sub_vector_t *sv, void *data, lar_found_t *found)
{
	switch(sv->id) {
		case LAR_SV_CORRELATOR:
			memcpy(&found->correlator, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RESOURCE_LSAP:
			memcpy(&found->lsap, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RESOURCE_MAC:
			memcpy(found->mac, data, LAR_SV_PAYLOAD(sv));
			break;

                default:
                        printf("found: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }

	return (0);
}

int lar_rx_build_query(sub_vector_t *sv, void *data, lar_query_t *query)
{
	switch(sv->id) {
		case LAR_SV_CORRELATOR:
			memcpy(&query->correlator, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_TARGET_NETID:
			memcpy(query->netid, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_GROUP_NAME:
			memcpy(query->group, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RTCAP:
			memcpy(&query->rtcap, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RETURN_CCE_MAC:
			memcpy(query->cce_mac, data, LAR_SV_PAYLOAD(sv));
			break;

                default:
                        printf("query: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }

	return (0);
}

int lar_rx_build_notify(sub_vector_t *sv, void *data, lar_notify_t *notify)
{
	switch(sv->id) {
		case LAR_SV_CORRELATOR:
			memcpy(&notify->correlator, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RESOURCE_LSAP:
			memcpy(&notify->lsap, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RESOURCE_MAC:
			memcpy(notify->mac, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RESOURCE_NETID:
			memcpy(notify->netid, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RESOURCE_NAME:
			memcpy(notify->name, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_GROUP_NAMES:
			lar_ssub_vector_parse(sv, lar_rx_build_group_names, notify->groups);
                        break;

		case LAR_SV_RTCAP:
			memcpy(&notify->rtcap, data, LAR_SV_PAYLOAD(sv));
			break;

		case LAR_SV_RETURN_CCE_MAC:
			memcpy(notify->mac, data, LAR_SV_PAYLOAD(sv));
			break;

                default:
                        printf("notify: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }

	return (0);
}

int lar_process_mv_solicit(major_vector_t *mv)
{
	lar_solicit_t sol;
	int err = 0;

	err = lar_sub_vector_parse(mv, lar_rx_build_solicit, &sol);
	if(err < 0)
		goto out;

	/* process solicit. */

out:	return (err);
}

int lar_process_mv_advertise(major_vector_t *mv)
{
	lar_advertise_t adv; 
        int err = 0;

        err = lar_sub_vector_parse(mv, lar_rx_build_advertise, &adv);
        if(err < 0)
                goto out; 

	/* process advertise. */

out:    return (err);
}
        
int lar_process_mv_find(major_vector_t *mv)
{
	lar_find_t find;
        int err = 0;

        err = lar_sub_vector_parse(mv, lar_rx_build_find, &find);
        if(err < 0)
                goto out; 

        /* process find. */

out:    return (err);
}
        
int lar_process_mv_found(major_vector_t *mv)
{
	lar_found_t found;
        int err = 0;

        err = lar_sub_vector_parse(mv, lar_rx_build_found, &found);
        if(err < 0)
                goto out; 

        /* process found. */

out:    return (err);
}
                
int lar_process_mv_query(major_vector_t *mv)
{
	lar_query_t query;
        int err = 0;

        err = lar_sub_vector_parse(mv, lar_rx_build_query, &query);
        if(err < 0)
                goto out; 

	/* process query. */
        
out:    return (err);
}

int lar_process_mv_notify(major_vector_t *mv)
{
	lar_notify_t notify;
        int err = 0;

        err = lar_sub_vector_parse(mv, lar_rx_build_notify, &notify);
        if(err < 0)
                goto out; 

	/* process notify. */

out:    return (err);
}

int lar_process_llc(struct lar_listen *lstn)
{
	struct sockaddr_llc from;
        int fromlen;            
        u_int8_t *pkt;
        int pktlen = 8192;
        int rxlen;              
	major_vector_t *mv;

        pkt = new_s(pktlen);    
        if(!pkt)                
                return (-ENOMEM);
        fromlen = sizeof(from);
        memset(&from, 0, sizeof(from));
        rxlen = recvfrom(lstn->listen_fd, pkt, pktlen, 0,
                (struct sockaddr *)&from, &fromlen);
	if(rxlen < 0) {
        	if(errno == EINTR) {
                	free(pkt);
                        return (0);
                }
		free(pkt);
		return (rxlen);
	}

	if(rxlen < sizeof(major_vector_t)) {
		free(pkt);
		return (-EINVAL);
	}

	mv = (major_vector_t *)pkt;
	switch(mv->id) {
		case LAR_MV_SOLICIT:	
			lar_process_mv_solicit(mv);	
			break;

		case LAR_MV_ADVERTISE:
			lar_process_mv_advertise(mv);
			break;

		case LAR_MV_FIND:
			lar_process_mv_find(mv);
			break;

		case LAR_MV_FOUND:
			lar_process_mv_found(mv);
			break;

		case LAR_MV_QUERY:
			lar_process_mv_query(mv);
			break;

		case LAR_MV_NOTIFY:
			lar_process_mv_notify(mv);
			break;

		default:
			printf("Unknown major vector 0x%02X\n", mv->id);
			break;
	}

	free(pkt);
	return (0);
}

int lar_load_timer(void)
{
	return (0);
}

int lar_load_unix(void)
{
	struct sockaddr_un un;
	int fd, err;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(fd < 0) {
		printf("%s: UNIX socket failed `%s'.\n", name_s, strerror(fd));
		return (fd);
	}

	memset(&un, 0, sizeof(struct sockaddr_un));
	un.sun_family = AF_UNIX;
	memcpy(&un.sun_path[1], _PATH_LAR_UDS, strlen(_PATH_LAR_UDS));
	err = bind(fd, (struct sockaddr *)&un, sizeof(un));
	if(err < 0) {
		printf("%s: UNIX bind failed `%s'.\n", name_s, strerror(fd));
		close (fd);
		return (err);
	}
	err = listen(fd, 40);
	if(err < 0) {
		printf("%s: UNIX listen failed `%s'.\n", name_s, strerror(err));
		close (fd);
		return (err);
	}

	lar_unix_fd = fd;
	lar_count_and_set_fds(fd, &lar_all_fds);
	return (0);
}

int lar_dev_set_group_maddr(struct lar_linfo *listen)
{
	struct sockaddr sa;
	struct ifreq ifr;
        int err;
       
	/* add all cce group mac address. */
	memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, listen->ifname);
        memset(&sa, 0, sizeof(struct sockaddr));
        sa.sa_family = ARPHRD_ETHER;
	memcpy(&sa.sa_data, (char *)lar_all_cce_gmac, 
		sizeof(lar_all_cce_gmac));
	memcpy((char *)&ifr.ifr_hwaddr, (char *)&sa,
                sizeof(struct sockaddr));
        err = ioctl(lar_ifr_fd, SIOCADDMULTI, &ifr);
        if(err < 0)
                return (err);

	syslog(LOG_ERR, "%s set %s\n", pr_ether(sa.sa_data), listen->ifname);

	/* add server or non-server group mac address. */ 
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, listen->ifname);
	memset(&sa, 0, sizeof(struct sockaddr));
        sa.sa_family = ARPHRD_ETHER;
	if(listen->igivname) {
		memcpy(&sa.sa_data, (char *)lar_server_gmac, 
			sizeof(lar_server_gmac));
	} else {
		memcpy(&sa.sa_data, (char *)lar_nserver_gmac,
			sizeof(lar_nserver_gmac));
	}
	memcpy((char *)&ifr.ifr_hwaddr, (char *)&sa,
        	sizeof(struct sockaddr));
        err = ioctl(lar_ifr_fd, SIOCADDMULTI, &ifr);
        if(err < 0)
               	return (err);

	syslog(LOG_ERR, "%s set %s\n", pr_ether(sa.sa_data), listen->ifname);

	return (0);
}

int lar_dev_unset_group_maddr(struct lar_linfo *listen)
{
        struct sockaddr sa;
        struct ifreq ifr;
        int err;

        /* add all cce group mac address. */
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, listen->ifname);
        memset(&sa, 0, sizeof(struct sockaddr));
        sa.sa_family = ARPHRD_ETHER;
        memcpy(&sa.sa_data, (char *)lar_all_cce_gmac,
                sizeof(lar_all_cce_gmac));
        memcpy((char *)&ifr.ifr_hwaddr, (char *)&sa,
                sizeof(struct sockaddr));
        err = ioctl(lar_ifr_fd, SIOCDELMULTI, &ifr);
        if(err < 0)
                return (err);

        syslog(LOG_ERR, "%s unset %s\n", pr_ether(sa.sa_data), listen->ifname);

        /* add server or non-server group mac address. */
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, listen->ifname);
        memset(&sa, 0, sizeof(struct sockaddr));
        sa.sa_family = ARPHRD_ETHER;
        if(listen->igivname) {
                memcpy(&sa.sa_data, (char *)lar_server_gmac,
                        sizeof(lar_server_gmac));
        } else {
                memcpy(&sa.sa_data, (char *)lar_nserver_gmac,
                        sizeof(lar_nserver_gmac));
        }
        memcpy((char *)&ifr.ifr_hwaddr, (char *)&sa,
                sizeof(struct sockaddr));
        err = ioctl(lar_ifr_fd, SIOCDELMULTI, &ifr);
        if(err < 0)
                return (err);

        syslog(LOG_ERR, "%s unset %s\n", pr_ether(sa.sa_data), listen->ifname);

        return (0);
}

int lar_dev_set_allmulti(struct lar_linfo *listen)
{
	struct ifreq ifr;
        int err;
        
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, listen->ifname);
        err = ioctl(lar_ifr_fd, SIOCGIFFLAGS, &ifr);
        if(err < 0)
                return (err);

        strcpy(ifr.ifr_name, listen->ifname);
	ifr.ifr_flags |= IFF_ALLMULTI;
        err = ioctl(lar_ifr_fd, SIOCSIFFLAGS, &ifr);
        if(err < 0)
                return (err);

	listen->allmulti = 1;
	syslog(LOG_ERR, "%s set ALLMULTI\n", listen->ifname);

	return (0);
}

int lar_dev_unset_allmulti(struct lar_linfo *listen)
{
        struct ifreq ifr;
        int err;

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, listen->ifname);
        err = ioctl(lar_ifr_fd, SIOCGIFFLAGS, &ifr);
        if(err < 0)
                return (err);
        
        strcpy(ifr.ifr_name, listen->ifname);
        ifr.ifr_flags |= ~IFF_ALLMULTI;
        err = ioctl(lar_ifr_fd, SIOCSIFFLAGS, &ifr);
        if(err < 0)
                return (err);

        syslog(LOG_ERR, "%s unset ALLMULTI\n", listen->ifname);

        return (0);
}

int lar_dev_get_ifindex(char *ifname)
{
	struct ifreq ifr;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	err = ioctl(lar_ifr_fd, SIOCGIFINDEX, &ifr);
	if(err < 0)
		return (err);
	return (ifr.ifr_ifindex);
}

int lar_dev_get_ifmac(char *ifname, char *ifmac)
{
	struct ifreq ifr;
        int err;

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, ifname);
        err = ioctl(lar_ifr_fd, SIOCGIFHWADDR, &ifr);
        if(err < 0)
                return (err);
	memcpy(ifmac, (char *)&ifr.ifr_hwaddr.sa_data,
                IFHWADDRLEN);

        return (0);
}

int lar_load_listen(struct lar_linfo *listen)
{
	struct sockaddr_llc laddr;
	struct lar_listen *lstn;
	int index, fd, err;

	index = lar_dev_get_ifindex(listen->ifname);
	if(index < 0) {
		printf("%s: ifindex failed for %s `%s'.\n", name_s, 
			listen->ifname, strerror(index));
		return (index);
	}
	listen->ifindex = index;

	err = lar_dev_get_ifmac(listen->ifname, listen->ifmac);
	if(err < 0) {
		printf("%s: ifmac failed `%s'.\n", name_s, strerror(err));
		return (err);
	}

	err = lar_dev_set_group_maddr(listen);
	if(err < 0) {
		err = lar_dev_set_allmulti(listen);
		if(err < 0) {
			printf("%s: failed to set multicast `%s'.\n", name_s, strerror(err));
			return (err);
		}
	}

	fd = socket(PF_LLC, SOCK_DGRAM, 0);
	if(fd < 0)
		return (fd);

	/* fill the our listen sockaddr_llc. */
        laddr.sllc_family       = PF_LLC;
        laddr.sllc_arphrd       = ARPHRD_ETHER; 
        laddr.sllc_ssap         = lar_config_info->lsap;
        memcpy(&laddr.sllc_smac, listen->ifmac, IFHWADDRLEN);
	err = bind(fd, (struct sockaddr *)&laddr, sizeof(laddr));
        if(err < 0) {
		printf("%s: bind failed `%s'.\n", name_s, strerror(err));
                close(fd);
                return (err);
        }       

	if(!new(lstn)) {
	        close(fd);
                return (-ENOMEM);
        }
	lstn->listen_fd	= fd;
	lstn->allmulti	= listen->allmulti;
	lstn->igivname	= listen->igivname;
	lstn->ifindex	= listen->ifindex;
	memcpy(&lstn->ifname, &listen->ifname, IFNAMSIZ);
        memcpy(&lstn->ifmac, &listen->ifmac, IFHWADDRLEN);
        lstn->next      = lar_listen_list;
        lar_listen_list = lstn;

	syslog(LOG_ERR, "CCE @ 0x%02X on %s using device %s",
		lar_config_info->lsap, pr_ether(listen->ifmac), listen->ifname);

	return (0);
}

static int lar_director(void)
{
        struct lar_listen *lstn;
	struct lar_client *clnt;
        fd_set readable;
        int fd, i;

        syslog(LOG_INFO, "Director activated.\n");

        sig_block();
        for(;;) {
                readable = lar_all_fds;
		lstn = NULL;
		clnt = NULL;

                sig_unblock();
                fd = select(lar_stats->highest_fd + 1, &readable,
                        NULL, NULL, NULL);
                sig_block();

                lar_stats->director_events++;
                if(fd < 0) {    /* check for immediate errors. */
                        if(fd < 0 && errno != EINTR) {
                                syslog(LOG_ERR, "select failed: %s",
                                        strerror(errno));
                                sleep(1);
                        }
                        lar_stats->director_errors++;
                        continue;
                }

                /* find which fd has an event for us. */
                for(i = 3; i <= lar_stats->highest_fd; i++) {
                        if(FD_ISSET(i, &readable)) {
				if(lar_unix_fd == i) {
					/* process new user. */
					lar_process_unix_accept(i);
					continue;
				}

				clnt = lar_find_client_by_fd(i);
				if(clnt) {
					/* process user data. */
					lar_process_user(clnt);
					continue;
				}

                                lstn = lar_find_listener_by_fd(i);
                                if(lstn) {
					/* process lar data. */
					lar_process_llc(lstn);
                                        continue;
                                }

                                /* well if we are here something is wrong. */
                                syslog(LOG_ERR, "Unable to find valid record for fd (%d)\n", i);
                                lar_stats->director_errors++;
                        }
                }
        }

        return (0);
}

void lar_signal_retry(int signum)
{
        (void)signum;
        return;
}       

void lar_signal_reload(int signum)
{
        (void)signum;
        return;
}       

void lar_signal_alarm(int signum)
{
        (void)signum;
        return;
}

/* user wants us dead, so lets cleanup and die. */
void lar_signal_goaway(int signum)
{
        struct lar_listen *lstn;
	struct lar_client *clnt;

        (void)signum;

	if(lar_unix_fd)
		close(lar_unix_fd);

	for(clnt = lar_client_list; clnt != NULL; clnt = clnt->next) {
		lar_count_and_clear_fds(clnt->client_fd, &lar_all_fds);
		close(clnt->client_fd);
	}
	lar_delete_client_list();

        for(lstn = lar_listen_list; lstn != NULL; lstn = lstn->next) {
                lar_count_and_clear_fds(lstn->listen_fd, &lar_all_fds);
                close(lstn->listen_fd);
        }
        lar_delete_listen_list();
        lar_delete_linfo_list();

        if(lar_config_info)
                free(lar_config_info);

        syslog(LOG_ERR, "Structured tear-down complete (%ld).",
                lar_stats->open_fds);
        free(lar_stats);

        (void)unlink(_PATH_LARDPID);
        closelog();

        exit (0);
}

void sig_init(void)
{       
        struct sigaction sa;

        sigemptyset(&emptymask);
        sigemptyset(&blockmask);
        sigaddset(&blockmask, SIGCHLD);
        sigaddset(&blockmask, SIGHUP);
        sigaddset(&blockmask, SIGALRM);

        memset(&sa, 0, sizeof(sa));
        sa.sa_mask = blockmask;
        sa.sa_handler = lar_signal_alarm;
        sigaction(SIGALRM, &sa, NULL);
        sa.sa_handler = lar_signal_reload;
        sigaction(SIGHUP, &sa, NULL);
        sa.sa_handler = lar_signal_goaway;
        sigaction(SIGTERM, &sa, NULL);
        sa.sa_handler = lar_signal_goaway;
        sigaction(SIGINT, &sa,  NULL);
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, NULL);
}

void sig_block(void)
{
        sigprocmask(SIG_BLOCK, &blockmask, NULL);
        if(blocked) {
            syslog(LOG_ERR, "internal error - signals already blocked\n");
            syslog(LOG_ERR, "please report to jschlst@samba.org\n");
        }
        blocked = 1;
}

void sig_unblock(void)
{
        sigprocmask(SIG_SETMASK, &emptymask, NULL);
        blocked = 0;
}

void sig_wait(void)
{
        sigsuspend(&emptymask);
}

void sig_preexec(void)
{
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_DFL;
        sigaction(SIGPIPE, &sa, NULL);

        sig_unblock();
}

static void logpid(void)
{
        FILE *fp;

        if((fp = fopen(_PATH_LARDPID, "w")) != NULL) {
                fprintf(fp, "%u\n", getpid());
                (void)fclose(fp);
        }
}

/* display the applications version and information. */
void version(void)
{
        printf("%s: %s %s\n%s\n", name_s, desc_s, version_s,
                maintainer_s);
        exit(1);
}

void help(void)
{
        printf("Usage: %s [-h] [-v] [-d level] [-f config]\n", name_s);
        exit(1);
}

int main(int argc, char **argv)
{
        int nodaemon = 0, err, c;

        if(!new(lar_stats))
                return (-ENOMEM);
        FD_ZERO(&lar_all_fds);
        while((c = getopt(argc, argv, "hvVf:d:")) != EOF) {
                switch(c) {
                        case 'd':       /* don't go into background. */
                                lar_stats->debug = nodaemon = atoi(optarg);
                                break;

                        case 'f':       /* Configuration file. */
                                strcpy(config_file, optarg);
                                break;

                        case 'V':       /* Display author and version. */
                        case 'v':       /* Display author and version. */
                                version();
                                break;

                        case 'h':       /* Display useless help information. */
                                help();
                                break;
                }
        }

	lar_ifr_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if(lar_ifr_fd < 0)
		lar_signal_goaway(0);

        err = load_config_file(config_file);
        if(err < 0)
                lar_signal_goaway(0);    /* clean&die */

        openlog(name_s, LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "%s %s", desc_s, version_s);

        if(nodaemon == 0)
                daemon(0, 0);

        /* log our pid for scripts. */
        logpid();

        /* setup signal handling */
        sig_init();

        err = load_config(lar_config_info);
        if(err < 0)
                lar_signal_goaway(0);    /* clean&die */

        /* we do the real work now, looping and directing. */
        err = lar_director();
        return (err);
}
