/* lard.c: lan address resolution daemon.
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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

/* required for llc sockets. */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/llc.h>

/* our stuff. */
#include "lar.h"
#include "lar_unix.h"
#include "lar_list.h"
#include "lar_timer.h"
#include "lar_vector.h"
#include "lard_load.h"
#include "lard.h"

#ifndef AF_LLC
#define AF_LLC          26
#define PF_LLC          AF_LLC
#endif

static char lar_server_gmac[]  = {0x03, 0x00, 0x00, 0x00, 0x00, 0x02};
static char lar_nserver_gmac[] = {0x03, 0x00, 0x00, 0x80, 0x00, 0x00};
static char lar_all_cce_gmac[] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x20};

char version_s[]                        = VERSION;
char name_s[]                           = "lard";
char desc_s[]                           = "Lan address resolution daemon";
char maintainer_s[]                     = "Jay Schulist <jschlst@samba.org>";
char web_s[]			 	= "http://www.linux-sna.org";

int lar_ifr_fd = -1;
fd_set lar_all_fds;
int lar_unix_fd;

char config_file[300]                   = _PATH_LARDCONF;
global *lar_config_info                 = NULL;
struct lar_statistics *lar_stats	= NULL;
static list_head(lar_client_list);
static list_head(lar_listen_list);
static list_head(lar_netent_list);

static sigset_t blockmask, emptymask;
static int blocked = 0;

extern void sig_block(void); 
extern void sig_unblock(void);

int hexdump(unsigned char *pkt_data, int pkt_len)
{
        int i;

        while(pkt_len > 0) {
                printf("   ");   /* Leading spaces. */
                /* Print the HEX representation. */
                for(i = 0; i < 8; ++i) {
                        if(pkt_len - (long)i > 0)
                                printf("%2.2X ", pkt_data[i] & 0xFF);
                        else
                                printf("  ");
                }

                printf(":");
                for(i = 8; i < 16; ++i) {
                        if(pkt_len - (long)i > 0)
                                printf("%2.2X ", pkt_data[i] & 0xFF);
                        else
                                printf("  ");
                }

                /* Print the ASCII representation. */
                printf("  ");
                for(i = 0; i < 16; ++i) {
                        if(pkt_len - (long)i > 0) {
                                if(isprint(pkt_data[i]))
                                        printf("%c", pkt_data[i]);
                                else
                                        printf(".");
                        }
                }

                printf("\n");
                pkt_len -= 16;
                pkt_data += 16;
        }

        printf("\n");

        return (0);
}

char *pr_ether(char *ptr)
{
        static char buff[64];

        snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X",
        	(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
                (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
        return(buff);
}

static char *pr_ebcdic_name(char *n)
{       
        static char *c;
        int len, i;
			        
        c = calloc(1, 20);
        memset(c, 0, sizeof(c)); 
        for (i = 0; i < 8 && (n[i] != 0x20); i++);
        len = i;
        strncpy(c, n, i);
        strncpy(c + len, "\0", 1);
        return c;
}

static void lar_count_and_set_fds(int fd, fd_set *all_fds)
{
        lar_stats->open_fds++;
        if (lar_stats->open_fds > lar_stats->wmark_fd)
                lar_stats->wmark_fd = lar_stats->open_fds;
        FD_SET(fd, all_fds);
        if (fd > lar_stats->highest_fd)
                lar_stats->highest_fd = fd;
        return;
}
        
static void lar_count_and_clear_fds(int fd, fd_set *all_fds)
{
        lar_stats->open_fds--;
        FD_CLR(fd, all_fds);
        return;
}

static struct lar_client *lar_client_find_by_fd(int fd)
{
	struct lar_client *l = NULL;
	struct list_head *le;

	list_for_each(le, &lar_client_list) {
		l = list_entry(le, struct lar_client, list);
                if(l->client_fd == fd)
			goto out;
		else
			l = NULL;
	}
out:	return l;
}

static int lar_client_delete_list(void)
{
	struct list_head *le, *se;
	struct lar_client *l;

	list_for_each_safe(le, se, &lar_client_list) {
		l = list_entry(le, struct lar_client, list);
		list_del((struct list_head *)l);
		free(l);
	}
        return 0;
}

static int lar_client_delete(struct lar_client *clnt)
{
	struct list_head *le, *se;
        struct lar_client *l;

        list_for_each_safe(le, se, &lar_client_list) {
                l = list_entry(le, struct lar_client, list);
                if (clnt->client_fd == l->client_fd) {
			list_del((struct list_head *)l);
	                free(l);
                        return 0;
                }
        }
        return -ENOENT;
}

static struct lar_listen *lar_listen_find_by_fd(int fd)
{
        struct lar_listen *l = NULL;
	struct list_head *le;

	list_for_each(le, &lar_listen_list) {
		l = list_entry(le, struct lar_listen, list);
                if (l->listen_fd == fd)
			goto out;
		else
			l = NULL;
	}
out:	return l;
}

static int lar_listen_delete_list(void)
{      
	struct list_head *le, *se;
        struct lar_listen *l;

        list_for_each_safe(le, se, &lar_listen_list) {
                l = list_entry(le, struct lar_listen, list);
                list_del((struct list_head *)l);
                free(l);
        }
        return 0;
}

static int lar_listen_delete_linfo_list(void)
{       
        struct lar_linfo *ent1, **clients1;
        
        clients1 = &lar_config_info->ll;
        while ((ent1 = *clients1) != NULL) {
                *clients1 = ent1->next;
                free(ent1);
        }
        return 0;
}

static struct lar_netent *lar_entity_find_by_record(lar_record_usr_t *recd)
{
	struct lar_netent *tmp = NULL;
	struct list_head *le;

	list_for_each(le, &lar_netent_list) {
		tmp = list_entry(le, struct lar_netent, list);
		if (tmp->record && !memcmp(recd->netid, tmp->record->netid, sizeof(lar_netid_t))
			&& !memcmp(recd->name, tmp->record->name, sizeof(lar_name_t))
                        && recd->rtcap == tmp->record->rtcap)
			goto out;
		else
			tmp = NULL;
	}
out:	return tmp;
}

static int lar_entity_delete_by_erase(lar_erase_usr_t *erase)
{
	struct lar_netent *tmp = NULL;
	struct list_head *le;

        list_for_each(le, &lar_netent_list) {
                tmp = list_entry(le, struct lar_netent, list);
                if (tmp->record && !memcmp(tmp->record->netid, erase->netid, 
			sizeof(lar_netid_t)) && !memcmp(tmp->record->name,
                        erase->name, sizeof(lar_name_t)))
                        break;
		else
			tmp = NULL;
        }            
	if (!tmp)
		return -ENOENT;

	list_del((struct list_head *)tmp);
	if (tmp->record)
		free(tmp->record);
	free(tmp);
	return 0;
}

static int lar_llc_tx_frame(struct lar_listen *lstn, char *dmac, void *data, int len)
{
	struct sockaddr_llc to;
	memcpy(&to, &lstn->laddr, sizeof(struct sockaddr_llc));
	memcpy(&to.sllc_dmac, dmac, LAR_MAX_SV_MAC_LEN);
	to.sllc_dsap = LLC_SAP_LAR;
	return sendto(lstn->listen_fd, data, len, 0, (struct sockaddr *)&to,
		sizeof(struct sockaddr_llc));
}

static int lar_llc_tx_find(struct lar_client *clnt, lar_find_usr_t *ufind)
{
	lar_find_pkt_t *find;
        struct list_head *le;
	char tempname[] = "FIXMENOW";

        /* build and transmit find. */
	if (!new(find))
		return -ENOMEM;
	find->correlator = clnt->client_fd;
	memcpy(find->tnetid, ufind->netid, sizeof(lar_netid_t));
	memcpy(find->tname, ufind->name, sizeof(lar_name_t));
        list_for_each(le, &lar_listen_list) {
		struct lar_listen *l = list_entry(le, struct lar_listen, list);
		major_vector_t *mv;
		memcpy(find->onetid, tempname, sizeof(lar_netid_t));
		memcpy(find->oname, tempname, sizeof(lar_name_t));
		memcpy(find->cce_mac, l->laddr.sllc_smac, sizeof(lar_mac_t));
		memcpy(find->omac, l->laddr.sllc_smac, sizeof(lar_mac_t));
		find->olsap = l->laddr.sllc_ssap;
		mv = lar_vect_tx_find(find);
                lar_llc_tx_frame(l, lar_all_cce_gmac, mv, mv->len);
                free(mv);
        }
	free(find);
        return 0;
}

static int lar_llc_tx_query(struct lar_client *clnt, lar_search_usr_t *srch)
{
	lar_query_pkt_t *query;
	struct list_head *le;

	/* build and transmit query. */
	if(!new(query))
		return -ENOMEM;
	query->correlator 	= clnt->client_fd;
	query->rtcap		= srch->rtcap;
	memcpy(query->netid, srch->netid, sizeof(lar_netid_t));
	memcpy(query->group, srch->group, sizeof(lar_group_t));
	list_for_each(le, &lar_listen_list) {
		struct lar_listen *l = list_entry(le, struct lar_listen, list);
		major_vector_t *mv;
		memcpy(query->cce_mac, l->laddr.sllc_smac, sizeof(lar_mac_t));
		mv = lar_vect_tx_query(query);
		lar_llc_tx_frame(l, lar_server_gmac, mv, mv->len);
		free(mv);
	}
	free(query);
	return 0;
}

static int lar_llc_tx_notify(struct lar_listen *lstn, lar_query_pkt_t *query,
        struct lar_netent *ne)
{
	lar_record_usr_t *recd = ne->record;
        lar_notify_pkt_t *notify;
        int i;

        /* build and transmit notify. */
        if (!new(notify))
                return -ENOMEM;
        notify->correlator      = query->correlator;
        notify->rtcap           = recd->rtcap;
        memcpy(notify->netid, recd->netid, sizeof(lar_netid_t));
        memcpy(notify->name, recd->name, sizeof(lar_name_t));
        memcpy(notify->cce_mac, lstn->laddr.sllc_smac, sizeof(lar_mac_t));
	for (i = 0; recd->groups[i] != NULL; i++)
		notify->groups[i] = recd->groups[i];
	notify->groups[i] = NULL;
        for (i = 0; recd->snpas[i] != NULL; i++) {
                major_vector_t *mv;
                notify->lsap = recd->snpas[i]->lsap;
                memcpy(notify->mac, recd->snpas[i]->mac, sizeof(lar_mac_t));
                mv = lar_vect_tx_notify(notify);
                lar_llc_tx_frame(lstn, query->cce_mac, mv, mv->len);
                free(mv);
        }
        free(notify);
        return 0;
}

static int lar_llc_tx_found(struct lar_listen *lstn, lar_find_pkt_t *find,
        struct lar_netent *ne)
{
	lar_record_usr_t *recd = ne->record;
        lar_found_pkt_t *found;
        major_vector_t *mv;
        
        /* build and transmit found. */
        if (!new(found))
                return -ENOMEM;
        found->correlator       = find->correlator;
        found->lsap             = recd->snpas[0]->lsap;
        memcpy(found->mac, recd->snpas[0]->mac, sizeof(lar_mac_t));
        mv = lar_vect_tx_found(found);
        lar_llc_tx_frame(lstn, find->cce_mac, mv, mv->len);
        free(found);
        free(mv);
        return 0; 
}

void lar_timer_expire_find(void *data);
void lar_timer_expire_query(void *data);
void lar_timer_expire_garbage(void *data);

static int lar_timer_start_garbage(void)
{
	timer_start(1, lar_stats->garbage.secs * 1000,
		lar_timer_expire_garbage, NULL);
	return 0;
}

void lar_timer_expire_garbage(void *data)
{
	struct list_head *le, *se;
	struct lar_netent *ent;
	time_t cur;

	list_for_each_safe(le, se, &lar_netent_list) {
		ent = list_entry(le, struct lar_netent, list);
		if (!ent->create)
			continue;
		time(&cur);
		if((cur - ent->create) < lar_stats->garbage_ttl)
			continue;
		list_del(&ent->list);
		free(ent);
 	}

	lar_timer_start_garbage();
        return;
}

static int lar_timer_start_find(struct lar_client *clnt)
{
	clnt->found_cnt = 0;
        timer_start(1, lar_stats->find.secs * 1000,
                lar_timer_expire_find, clnt);
        return 0;
}        

void lar_timer_expire_find(void *data)
{
	struct lar_client *clnt = data;
	lar_find_usr_t *find;

	if (!clnt || !clnt->find)
		return;
	find = clnt->find;
	if (clnt->found_cnt)	/* got okay rsp. */
		return;

	if (clnt->find_cnt == lar_stats->find.count) {
		lar_unix_send_errno(clnt->client_fd, ENOENT);
		return;
	}

	/* resend find frame. */
	lar_llc_tx_find(clnt, find);
	lar_timer_start_find(clnt);
	clnt->find_cnt++;
	return;
}

static int lar_timer_start_query(struct lar_client *clnt)
{
        timer_start(1, lar_stats->query.secs * 1000, 
		lar_timer_expire_query, clnt);
        return 0;
}

void lar_timer_expire_query(void *data)
{
	struct lar_client *clnt = data;
	lar_search_usr_t *srch = clnt->srch;
	struct list_head *le;
	struct larmsg *lh;
	int err = ENOENT;
	int entries;

	/* get all entries that match search from list. 
	 * build message and send back to client.
	 */
	if(list_empty(&lar_netent_list)) {
		lar_unix_send_errno(clnt->client_fd, err);
		printf("return\n");
		return;
	}

	err = 0;
	entries = 0;
	lh = larmsg_put(LAR_OP_SEARCH, sizeof(*lh));
	list_for_each(le, &lar_netent_list) {
		struct lar_netent *ne = list_entry(le, struct lar_netent, list);
		lar_record_usr_t *recd = ne->record;
		int i;
		if (!recd)
			continue;
		if (strncmp(srch->netid, recd->netid, 8) 
			|| srch->rtcap != recd->rtcap)
			continue;
		for (i = 0; recd->groups[i] != NULL; i++) {
			if(!strncmp(srch->group, *recd->groups[i], 8))
				break;
                }
		if (recd->groups[i] == NULL)
			continue;
		for (i = 0; recd->snpas[i] != NULL; i++) {
			lar_member_t *me;
			if (!new(me))
				continue;
			memcpy(&me->name, recd->name, 8);
			memcpy(&me->snpa, recd->snpas[i], sizeof(lar_snpa_t));
			lh = lara_put(lh, LARA_MEMBER, sizeof(lar_member_t), me);
			free(me);
		}
		entries++;
	}
	lh = lara_put(lh, LARA_ERR, sizeof(err), &err);
	if (!entries)
		lar_unix_send_errno(clnt->client_fd, ENOENT);
	else
		lar_unix_send(clnt->client_fd, lh, lh->len);
	free(lh);
	return;
}

static int lar_process_unix_record(struct lar_client *clnt, struct larmsg *lh)
{
	lar_record_usr_t *record;
	struct lar_netent *ent;
        int err = 0;

	/* gather the unix record data. */
        if (!new(record)) {
                err = ENOMEM;
                goto out_r;
        }
        err = lar_attr_parse(lh, lar_unix_rx_record, record);
        if (err < 0) {
                free(record);
                goto out_r;
        }
	ent = lar_entity_find_by_record(record);
	if (ent) {
		err = EEXIST;
                free(record);
                goto out_r;
        }

	/* allocate new entry and append it to the list. */
        if (!new(ent)) {
                err = ENOMEM;
		free(record);
                goto out_r;
        }
	ent->create = 0;
	ent->record = record;
        list_add_tail((struct list_head *)ent, &lar_netent_list);
out_r:  lar_unix_send_errno(clnt->client_fd, err);
        return 0;
}

static int lar_process_unix_erase(struct lar_client *clnt, struct larmsg *lh)
{
	lar_erase_usr_t *erase;
        int err = 0;

	/* gather the unix erase data. */
        if (!new(erase)) {
                err = ENOMEM;
                goto out_r;
        }       
        err = lar_attr_parse(lh, lar_unix_rx_erase, erase);
        if (err < 0) {
                free(erase);
                goto out_r;
        }     

        /* delete the entry for the list. */
        err = lar_entity_delete_by_erase(erase);
        if (err < 0) {
                err = ENOENT;
                free(erase);
                goto out_r;
        }
	free(erase);
out_r:  lar_unix_send_errno(clnt->client_fd, err);
        return 0;
}

static int lar_process_unix_search(struct lar_client *clnt, struct larmsg *lh)
{
	lar_search_usr_t *srch;
        int err = 0;

        /* gather the unix search data. */
        if (!new(srch)) {
                err = ENOMEM;
                goto out_er;
        }
        err = lar_attr_parse(lh, lar_unix_rx_search, srch);
        if(err < 0) {
                free(srch);
                goto out_er;
        }

	/* tx frame. */
	err = lar_llc_tx_query(clnt, srch);
	if (err < 0) {
		free(srch);
		goto out_er;
	}

	/* set query timer to maximum and AF=0. */
	clnt->af	= 0;
	clnt->srch 	= srch;
	lar_timer_start_query(clnt);
	goto out;

        /* send error response. */
out_er: err = lar_unix_send_errno(clnt->client_fd, err);
        if(err < 0) {
                printf("%s: send to user failed `%s'.\n", name_s, strerror(err));
                return (err);
        }
out:	return (0);
}

static int lar_process_unix_find(struct lar_client *clnt, struct larmsg *lh)
{
	lar_find_usr_t *find;
        int err = 0;
        
        /* gather the unix find data. */
        if (!new(find)) {
                err = ENOMEM;
                goto out_er;
        }
        err = lar_attr_parse(lh, lar_unix_rx_find, find);
        if(err < 0) {
                free(find);
                goto out_er;
        }
        
        /* tx frame. */
        err = lar_llc_tx_find(clnt, find);
        if(err < 0) {
                free(find);
                goto out_er;
        }

	/* set find timer to maximum. */
	clnt->find_cnt	= 1;
        clnt->find      = find;
        lar_timer_start_find(clnt);
	goto out;

	/* send error response. */
out_er: err = lar_unix_send_errno(clnt->client_fd, err);
        if(err < 0) {
                printf("%s: send to user failed `%s'.\n", name_s, strerror(err));
                return (err);
        }
out:    return (0);
}

static int lar_process_unix_find_member(struct lar_client *clnt, struct larmsg *lh)
{
	int err;

        /* send response. */
        err = lar_unix_send_errno(clnt->client_fd, EOPNOTSUPP);
        if(err < 0) {
                printf("%s: send to user failed `%s'.\n", name_s, strerror(err));
                return (err);
        }

	return (0);
}

static int lar_process_mv_solicit(struct lar_listen *lstn, major_vector_t *mv)
{
	lar_solicit_pkt_t sol;
	int err = 0;

	err = lar_sub_vector_parse(mv, lar_vect_rx_solicit, &sol);
	if(err < 0)
		goto out;

	printf("mv: solicit\n");
	/* process solicit. */

out:	return (err);
}

static int lar_process_mv_advertise(struct lar_listen *lstn, major_vector_t *mv)
{
	lar_advertise_pkt_t adv; 
        int err = 0;

        err = lar_sub_vector_parse(mv, lar_vect_rx_advertise, &adv);
        if(err < 0)
                goto out; 

	printf("mv: advertise\n");
	/* process advertise. */

out:    return (err);
}

static int lar_process_mv_find(struct lar_listen *lstn, major_vector_t *mv)
{
	struct lar_netent *ent;
        lar_record_usr_t *recd;
	struct list_head *le;
	lar_find_pkt_t *find;
        int err = 0;

	if (!new(find))
		return -ENOMEM;
        err = lar_sub_vector_parse(mv, lar_vect_rx_find, find);
        if (err < 0)
                goto out; 

	/* for each matching entry in our table.
         *  build found frame and tx to return origin cce.
         */
        list_for_each(le, &lar_netent_list) {
                struct lar_netent *ne = list_entry(le, struct lar_netent, list);
                if (!ne->record || memcmp(ne->record->netid, find->tnetid, 
			find->tnetid_len) || memcmp(ne->record->name,
                        find->tname, find->tname_len))
                        continue;
                lar_llc_tx_found(lstn, find, ne);
        }

	/* cache entry. */
        if (!new(recd))
                goto out;
        memcpy(recd->name, find->oname, sizeof(lar_name_t));
        memcpy(recd->netid, find->onetid, sizeof(lar_netid_t));
        recd->groups[0] = new_s(sizeof(lar_group_t));
        recd->snpas[0] = new_s(sizeof(lar_snpa_t));
        memcpy(recd->snpas[0]->mac, find->omac, sizeof(lar_mac_t));
        memcpy(&recd->snpas[0]->lsap, &find->olsap, sizeof(lar_lsap_t));
        ent = lar_entity_find_by_record(recd);
        if (ent) {
                free(recd);
                goto out;
        }
        if (!new(ent)) {
                free(recd);
                goto out;
        }
        time(&ent->create);
        ent->record = recd;
        list_add_tail((struct list_head *)ent, &lar_netent_list);

out:	free(find);
    	return (err);
}

static int lar_process_mv_found(struct lar_listen *lstn, major_vector_t *mv)
{
	struct lar_client *clnt;
	struct lar_netent *ent;
	lar_record_usr_t *recd;
	lar_found_pkt_t *found;
	struct larmsg *lh;
        lar_snpa_t snpa;
        int err = 0;

	if (!new(found))
		return -ENOMEM;
        err = lar_sub_vector_parse(mv, lar_vect_rx_found, found);
        if (err < 0)
                goto out; 

	/* check if we are expecting this notify. */
        clnt = lar_client_find_by_fd(found->correlator);
        if (!clnt)
		goto out;
	clnt->found_cnt = 1;
	lh = larmsg_put(LAR_OP_FIND, sizeof(*lh));
	memcpy(&snpa.lsap, &found->lsap, 1);
	memcpy(snpa.mac, found->mac, 6);
	lh = lara_put(lh, LARA_SNPA, sizeof(lar_snpa_t), &snpa);
        lh = lara_put(lh, LARA_ERR, sizeof(err), &err);
        err = lar_unix_send(clnt->client_fd, lh, lh->len);
	free(lh);

	/* cache entry. */
	if (!new(recd))
		goto out;
        memcpy(recd->name, clnt->find->name, sizeof(lar_name_t));
        memcpy(recd->netid, clnt->find->netid, sizeof(lar_netid_t));
	recd->groups[0] = new_s(sizeof(lar_group_t));
        recd->snpas[0] = new_s(sizeof(lar_snpa_t));
        memcpy(recd->snpas[0]->mac, found->mac, sizeof(lar_mac_t));
        memcpy(&recd->snpas[0]->lsap, &found->lsap, sizeof(lar_lsap_t));
        ent = lar_entity_find_by_record(recd);
        if (ent) {
                free(recd);
                goto out;
        }
        if (!new(ent)) {
                free(recd);
                goto out;
        }
        time(&ent->create);
        ent->record = recd;
        list_add_tail((struct list_head *)ent, &lar_netent_list);
out:	free(found);
    	return (err);
}

static int lar_process_mv_query(struct lar_listen *lstn, major_vector_t *mv)
{
	lar_query_pkt_t *query;
	struct list_head *le;
        int err = 0, i;

	if (!new(query))
		return -ENOMEM;
        err = lar_sub_vector_parse(mv, lar_vect_rx_query, query);
        if (err < 0)
                goto out; 

	/* for each matching entry in our table.
	 *  build notify frame and tx to lstn.
	 */
	list_for_each(le, &lar_netent_list) {
		struct lar_netent *ne = list_entry(le, struct lar_netent, list);
		lar_record_usr_t *recd = ne->record;
		if (!recd || memcmp(recd->netid, query->netid, query->netid_len)
			|| recd->rtcap != query->rtcap)
			continue;
		for (i = 0; recd->groups[i] != NULL; i++) {
			if(!memcmp(recd->groups[i], query->group,
				query->group_len))
				break;
		}
		if (recd->groups[i] == NULL)
			continue;
		lar_llc_tx_notify(lstn, query, ne);
	}
out:	free(query);
        return err;
}

static int lar_process_mv_notify(struct lar_listen *lstn, major_vector_t *mv)
{
	lar_notify_pkt_t *notify;
	lar_record_usr_t *recd;
	struct lar_client *clnt;
	struct lar_netent *ent;
        int i, err = 0;

	/* gather notify data from the network. */
	if (!new(notify))
		return -ENOMEM;
        err = lar_sub_vector_parse(mv, lar_vect_rx_notify, notify);
        if (err < 0) {
		free(notify);
		goto out;
	}

	/* check if we are expecting this notify. */
	clnt = lar_client_find_by_fd(notify->correlator);
	if (!clnt) {
		free(notify);
		return 0;
	}
	if (!new(recd)) {
		free(notify);
		return -ENOMEM;
	}
	memcpy(recd->name, notify->name, sizeof(lar_name_t));
	memcpy(recd->netid, notify->netid, sizeof(lar_netid_t));
	memcpy(&recd->rtcap, &notify->rtcap, sizeof(lar_rtcap_t));
	for (i = 0; notify->groups[i] != NULL; i++) {
		recd->groups[i] = new_s(sizeof(lar_group_t));
		memcpy(recd->groups[i], notify->groups[i], 
			sizeof(lar_group_t));
	}
	recd->groups[i] = NULL;
	recd->snpas[0] = new_s(sizeof(lar_snpa_t));
	memcpy(recd->snpas[0]->mac, notify->mac, sizeof(lar_mac_t));
	memcpy(&recd->snpas[0]->lsap, &notify->lsap, sizeof(lar_lsap_t));
	ent = lar_entity_find_by_record(recd);
        if (ent) {
                err = EEXIST;
		free(notify);
                free(recd);
                goto out;
        }

	/* we have found a valid entity from the network. */
	if (!new(ent)) {
                err = ENOMEM;
                free(notify);
		free(recd);
                goto out;
        }
	clnt->af = 1;
        time(&ent->create);
	ent->record = recd;
        list_add_tail((struct list_head *)ent, &lar_netent_list);
	free(notify);
out:    return err;
}

static int lar_process_llc(struct lar_listen *lstn)
{
	struct sockaddr_llc from;
        int fromlen = sizeof(from);
        int rxlen, pktlen = 8192;
	major_vector_t *mv;
	u_int8_t *pkt;

        pkt = new_s(pktlen);    
        if(!pkt)                
                return -ENOMEM;
        memset(&from, 0, sizeof(from));
        rxlen = recvfrom(lstn->listen_fd, pkt, pktlen, 0,
                (struct sockaddr *)&from, &fromlen);
	if (rxlen < 0)
		goto out;
	if (rxlen < sizeof(major_vector_t)) {
		free(pkt);
		return -EINVAL;
	}

	mv = (major_vector_t *)pkt;
	switch (mv->id) {
		case LAR_MV_SOLICIT:	
			lar_process_mv_solicit(lstn, mv);
			break;

		case LAR_MV_ADVERTISE:
			lar_process_mv_advertise(lstn, mv);
			break;

		case LAR_MV_FIND:
			lar_process_mv_find(lstn, mv);
			break;

		case LAR_MV_FOUND:
			lar_process_mv_found(lstn, mv);
			break;

		case LAR_MV_QUERY:
			lar_process_mv_query(lstn, mv);
			break;

		case LAR_MV_NOTIFY:
			lar_process_mv_notify(lstn, mv);
			break;

		default:
			printf("Unknown major vector 0x%02X\n", mv->id);
			break;
	}
out:	free(pkt);
	return 0;
}

static int lar_process_user(struct lar_client *clnt)
{
        int rxlen, pktlen = 8192;
	struct larmsg *lh;
        u_int8_t *pkt;

        pkt = new_s(pktlen);    
        if (!pkt)
                return -ENOMEM;

        /* process user request. */
        rxlen = recv(clnt->client_fd, pkt, pktlen, 0);
        if (rxlen < 0 || rxlen == 0) {
                lar_count_and_clear_fds(clnt->client_fd, &lar_all_fds);
                close(clnt->client_fd);
                lar_client_delete(clnt);
		free(pkt);
                return 0;
        }
	if (rxlen < sizeof(struct larmsg)) {
                free(pkt);
                return -EINVAL;
        }
        lh = (struct larmsg *)pkt;
        switch (lh->type) {
                case LAR_OP_RECORD:
                        lar_process_unix_record(clnt, lh);
                        break;

                case LAR_OP_ERASE:
                        lar_process_unix_erase(clnt, lh);
                        break;

                case LAR_OP_SEARCH:
                        lar_process_unix_search(clnt, lh);
                        break;

                case LAR_OP_FIND:
                        lar_process_unix_find(clnt, lh);
                        break;

                case LAR_OP_FIND_MEMBER:
                        lar_process_unix_find(clnt, lh);
                        break;

                default:
                        lar_unix_send_errno(clnt->client_fd, EINVAL);
        }
	free(pkt);
        return 0;
}

static int lar_process_unix_accept(int fd)
{
        struct sockaddr_un from;
        int fromlen = sizeof(from);
        struct lar_client *clnt;
        int client_fd;

        memset(&from, 0, sizeof(from));
        client_fd = accept(fd, (struct sockaddr *)&from, &fromlen);
        if (client_fd < 0)
                return client_fd;
        if (!new(clnt))
                return -ENOMEM;
        clnt->client_fd = client_fd;
        memcpy(&clnt->client_addr, &from, sizeof(from));
        list_add_tail((struct list_head *)clnt, &lar_client_list);
        lar_count_and_set_fds(client_fd, &lar_all_fds);
        return 0;
}

int lar_load_timer(struct lar_tinfo *t)
{
	if (!strcmp(t->name, "garbage"))
		memcpy(&lar_stats->garbage, t, sizeof(*t));
	if (!strcmp(t->name, "query"))
		memcpy(&lar_stats->query, t, sizeof(*t));
	if (!strcmp(t->name, "solicit"))
		memcpy(&lar_stats->solicit, t, sizeof(*t));
	if (!strcmp(t->name, "advertise"))
		memcpy(&lar_stats->advertise, t, sizeof(*t));
	if (!strcmp(t->name, "find"))
		memcpy(&lar_stats->find, t, sizeof(*t));
	return 0;
}

int lar_load_unix(void)
{
	struct sockaddr_un un;
	int fd, err;

	/* setup local unix socket interface. */
	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("%s: UNIX socket failed `%s'.\n", name_s, strerror(fd));
		return fd;
	}
	memset(&un, 0, sizeof(struct sockaddr_un));
	un.sun_family = AF_UNIX;
	memcpy(&un.sun_path[1], _PATH_LAR_UDS, strlen(_PATH_LAR_UDS));
	err = bind(fd, (struct sockaddr *)&un, sizeof(un));
	if (err < 0) {
		printf("%s: UNIX bind failed `%s'.\n", name_s, strerror(fd));
		close (fd);
		return err;
	}
	err = listen(fd, 40);
	if (err < 0) {
		printf("%s: UNIX listen failed `%s'.\n", name_s, strerror(err));
		close (fd);
		return err;
	}
	lar_unix_fd = fd;
	lar_count_and_set_fds(fd, &lar_all_fds);
	return 0;
}

static int lar_dev_set_group_maddr(struct lar_linfo *listen)
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

static int lar_dev_unset_group_maddr(struct lar_linfo *listen)
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

        syslog(LOG_ERR, "CCE displable %s for %s\n", pr_ether(sa.sa_data), 
		listen->ifname);
        return 0;
}

static int lar_dev_set_allmulti(struct lar_linfo *listen)
{
	struct ifreq ifr;
        int err;
        
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, listen->ifname);
        err = ioctl(lar_ifr_fd, SIOCGIFFLAGS, &ifr);
        if (err < 0)
                return err;
        strcpy(ifr.ifr_name, listen->ifname);
	ifr.ifr_flags |= IFF_ALLMULTI;
        err = ioctl(lar_ifr_fd, SIOCSIFFLAGS, &ifr);
        if (err < 0)
                return err;
	listen->allmulti = 1;
	return 0;
}

static int lar_dev_unset_allmulti(struct lar_linfo *listen)
{
        struct ifreq ifr;
        int err;

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, listen->ifname);
        err = ioctl(lar_ifr_fd, SIOCGIFFLAGS, &ifr);
        if (err < 0)
                return err;
        strcpy(ifr.ifr_name, listen->ifname);
        ifr.ifr_flags |= ~IFF_ALLMULTI;
        err = ioctl(lar_ifr_fd, SIOCSIFFLAGS, &ifr);
        if (err < 0)
                return err;
        syslog(LOG_ERR, "CCE disabling allmulti for dev(%s).\n", listen->ifname);
        return 0;
}

static int lar_dev_get_ifindex(char *ifname)
{
	struct ifreq ifr;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	err = ioctl(lar_ifr_fd, SIOCGIFINDEX, &ifr);
	if (err < 0)
		return err;
	return ifr.ifr_ifindex;
}

static int lar_dev_get_ifmac(char *ifname, char *ifmac)
{
	struct ifreq ifr;
        int err;

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, ifname);
        err = ioctl(lar_ifr_fd, SIOCGIFHWADDR, &ifr);
        if (err < 0)
                return err;
	memcpy(ifmac, (char *)&ifr.ifr_hwaddr.sa_data,
                IFHWADDRLEN);
        return 0;
}

static int lar_load_group_mac(char *smac, char *dmac)
{
	struct lar_listen *lstn;
	struct sockaddr_llc laddr;
	int fd, err;

	/* fill the our listen sockaddr_llc. */
	fd = socket(PF_LLC, SOCK_DGRAM, 0);
        if (fd < 0)
                return fd;
	memset(&laddr, 0, sizeof(laddr));
        laddr.sllc_family       = PF_LLC;
        laddr.sllc_arphrd       = ARPHRD_ETHER;
        laddr.sllc_ssap         = lar_config_info->lsap;
	memcpy(&laddr.sllc_smac, smac, IFHWADDRLEN);
        memcpy(&laddr.sllc_mmac, dmac, IFHWADDRLEN);
        err = bind(fd, (struct sockaddr *)&laddr, sizeof(laddr));
        if (err < 0) {
                printf("%s: bind failed `%s'.\n", name_s, strerror(errno));
                close(fd);
                return err;
        }

	/* allocate the listen structure. */
        if (!new(lstn)) {
                close(fd);
                return -ENOMEM;
        }
        lstn->listen_fd = fd;
        memcpy(&lstn->ifmac, dmac, IFHWADDRLEN);
        memcpy(&lstn->laddr, &laddr, sizeof(struct sockaddr_llc));
        list_add_tail((struct list_head *)lstn, &lar_listen_list);
	lar_count_and_set_fds(fd, &lar_all_fds);
        syslog(LOG_ERR, "CCE GROUP %s@0x%02X", pr_ether(lstn->ifmac),
                lar_config_info->lsap);
	return 0;
}

int lar_load_listen(struct lar_linfo *listen)
{
	struct sockaddr_llc laddr;
	struct lar_listen *lstn;
	int index, fd, err;

	/* setup the physical interface. */
	index = lar_dev_get_ifindex(listen->ifname);
	if (index < 0) {
		printf("%s: ifindex failed for %s `%s'.\n", name_s, 
			listen->ifname, strerror(index));
		return index;
	}
	listen->ifindex = index;
	err = lar_dev_get_ifmac(listen->ifname, listen->ifmac);
	if (err < 0) {
		printf("%s: ifmac failed `%s'.\n", name_s, strerror(err));
		return err;
	}
	err = lar_dev_set_group_maddr(listen);
	if (err < 0) {
		err = lar_dev_set_allmulti(listen);
		if (err < 0) {
			printf("%s: failed to set multicast and allmulti: `%s'.\n", 
				name_s, strerror(err));
			return err;
		}
	}

	/* fill the our listen sockaddr_llc. */
	fd = socket(PF_LLC, SOCK_DGRAM, 0);
	if (fd < 0)
		return fd;
        laddr.sllc_family       = PF_LLC;
        laddr.sllc_arphrd       = ARPHRD_ETHER; 
        laddr.sllc_ssap         = lar_config_info->lsap;
        memcpy(&laddr.sllc_smac, listen->ifmac, IFHWADDRLEN);
	err = bind(fd, (struct sockaddr *)&laddr, sizeof(laddr));
        if (err < 0) {
		printf("%s: bind failed `%s'.\n", name_s, strerror(err));
                close(fd);
                return err;
        }       

	/* allocate the listen information. */
	if(!new(lstn)) {
	        close(fd);
                return -ENOMEM;
        }
	lstn->listen_fd	= fd;
	lstn->allmulti	= listen->allmulti;
	lstn->igivname	= listen->igivname;
	lstn->ifindex	= listen->ifindex;
	memcpy(&lstn->ifname, &listen->ifname, IFNAMSIZ);
        memcpy(&lstn->ifmac, &listen->ifmac, IFHWADDRLEN);
	memcpy(&lstn->laddr, &laddr, sizeof(struct sockaddr_llc));
	list_add_tail((struct list_head *)lstn, &lar_listen_list);
	lar_count_and_set_fds(fd, &lar_all_fds);
	syslog(LOG_ERR, "CCE %s@0x%02X allmulti=%d", pr_ether(listen->ifmac),
		lar_config_info->lsap, listen->allmulti);

	/* load the group mac addresses. */
	lar_load_group_mac(listen->ifmac, lar_server_gmac);
        lar_load_group_mac(listen->ifmac, lar_nserver_gmac);
        lar_load_group_mac(listen->ifmac, lar_all_cce_gmac);
	return 0;
}

static int lar_utable_open(void)
{
	int err;
	unlink(_PATH_LAR_USER_TABLE);
	err = mkfifo(_PATH_LAR_USER_TABLE, 
		S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if(err < 0 && errno != EEXIST)
		return err;
	return 0;
}

static int lar_utable_close(void)
{
	unlink(_PATH_LAR_USER_TABLE);
	return 0;
}

static int lar_utable_check(void)
{
	struct lar_netent *ent = NULL;
        struct list_head *le;
	int blen = 8192;
	int fd, len = 0;
	char *buf;

	fd = open(_PATH_LAR_USER_TABLE, O_WRONLY | O_NONBLOCK, 0);
	if (fd < 0)
		return fd;
	buf = new_s(blen);
	if (!blen)
		return -ENOMEM;
	len += sprintf(buf + len, "age    netid.name        rtcap group(s) snpa(s)                  \n");
        list_for_each(le, &lar_netent_list) {
		lar_record_usr_t *recd;
		char nname[20];
		time_t cur;
		int i, birth;
		
                ent = list_entry(le, struct lar_netent, list);
		recd = ent->record;
		if (!ent->record)
			continue;
		if (blen - len < 1000) {
			buf = realloc(buf, blen * 2);
			blen = blen * 2;
		}
		if (ent->create) {
			time(&cur);
			birth = cur - ent->create;
		} else
			birth = 0;
		sprintf(nname, "%s.%s", pr_ebcdic_name(recd->netid),
					pr_ebcdic_name(recd->name));
		len += sprintf(buf + len, "%-6d %-17s 0x%02X  ", birth, nname,
			recd->rtcap);
		len += sprintf(buf + len, "%-8s %-17s@0x%02X",
			pr_ebcdic_name((char *)recd->groups[0]),
			pr_ether(recd->snpas[0]->mac), recd->snpas[0]->lsap);
		len += sprintf(buf + len, "\n");
		for (i = 1; recd->groups[i] != NULL; i++) {
			len += sprintf(buf + len, "%-31s", " ");
			len += sprintf(buf + len, "%-8s ",
				pr_ebcdic_name((char *)recd->groups[i]));
			if (recd->snpas[i] != NULL) {
				len += sprintf(buf + len, "%-17s@0x%02X",
					pr_ether(recd->snpas[i]->mac), 
					recd->snpas[i]->lsap);
			}
			len += sprintf(buf + len, "\n");
		}
		for (; recd->snpas[i] != NULL; i++) {
			len += sprintf(buf + len, "%-39s %-17s@0x%02X", " ",
                        	pr_ether(recd->snpas[i]->mac), 
                        	recd->snpas[i]->lsap);
			len += sprintf(buf + len, "\n");
		}
        }
	/* write the buffer to user. */
	write(fd, buf, len);
	free(buf);
	close(fd);
	usleep(1000);
	return 0;
}

static int lar_director(void)
{
        struct lar_listen *lstn;
	struct lar_client *clnt;
	struct timeval timeout;
        fd_set readable;
        int fd, i;

        syslog(LOG_INFO, "Director activated.\n");

        sig_block();
        for(;;) {
                readable = lar_all_fds;
		lstn = NULL;
		clnt = NULL;

		memset(&timeout, 0, sizeof(timeout));
	        timeout.tv_usec = LAR_DIR_TIMEOUT;
		
                sig_unblock();
                fd = select(lar_stats->highest_fd + 1, &readable,
                        NULL, NULL, &timeout);
                sig_block();

		if (fd == 0) {
			lar_utable_check();
			continue;
		}
		
                lar_stats->director_events++;
                if (fd < 0) {    /* check for immediate errors. */
                        if (fd < 0 && errno != EINTR) {
                                syslog(LOG_ERR, "select failed: %s",
                                        strerror(errno));
                                sleep(1);
                        }
                        lar_stats->director_errors++;
                        continue;
                }

                /* find which fd has an event for us. */
                for (i = 3; i <= lar_stats->highest_fd; i++) {
                        if (FD_ISSET(i, &readable)) {
				if (lar_unix_fd == i) {
					/* process new user. */
					lar_process_unix_accept(i);
					continue;
				}

				clnt = lar_client_find_by_fd(i);
				if (clnt) {
					/* process user request. */
					lar_process_user(clnt);
					continue;
				}

                                lstn = lar_listen_find_by_fd(i);
                                if (lstn) {
					/* process lar data. */
					lar_process_llc(lstn);
                                        continue;
                                }

                                /* well if we are here something is wrong. */
                                syslog(LOG_ERR, "Unknown file descriptor (%d).\n", i);
                                lar_stats->director_errors++;
                        }
                }
        }
        return 0;
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
	struct list_head *le;
        struct lar_listen *lstn;
	struct lar_client *clnt;

        (void)signum;
	lar_utable_close();
	if (lar_unix_fd)
		close(lar_unix_fd);
	list_for_each(le, &lar_client_list) {
		clnt = list_entry(le, struct lar_client, list);
		lar_count_and_clear_fds(clnt->client_fd, &lar_all_fds);
		close(clnt->client_fd);
	}
	lar_client_delete_list();
	list_for_each(le, &lar_listen_list) {
		lstn = list_entry(le, struct lar_listen, list);
                lar_count_and_clear_fds(lstn->listen_fd, &lar_all_fds);
                close(lstn->listen_fd);
        }
        lar_listen_delete_list();
        lar_listen_delete_linfo_list();
	if (lar_ifr_fd)
		close(lar_ifr_fd);
        if (lar_config_info)
                free(lar_config_info);
        syslog(LOG_ERR, "Structured tear-down complete (%ld).",
                lar_stats->open_fds);
        free(lar_stats);
        (void)unlink(_PATH_LARDPID);
        closelog();
        exit(0);
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
        if (blocked) {
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

static void logpid(char *path)
{
        FILE *fp;

        if ((fp = fopen(path, "w")) != NULL) {
                fprintf(fp, "%u\n", getpid());
                (void)fclose(fp);
        }
}

/* display the applications version and information. */
static void version(void)
{
        printf("%s: %s %s\n%s\n", name_s, desc_s, version_s,
                maintainer_s);
	printf("%s\n", web_s);
        exit(1);
}

static void help(void)
{
        printf("Usage: %s [-h] [-v] [-d level] [-f config]\n", name_s);
        exit(1);
}

int main(int argc, char **argv)
{
        int nodaemon = 0, err, c;

        if (!new(lar_stats))
                return (-ENOMEM);
        FD_ZERO(&lar_all_fds);
        while ((c = getopt(argc, argv, "hvVf:d:")) != EOF) {
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
	if (lar_ifr_fd < 0)
		lar_signal_goaway(0);

        err = load_config_file(config_file);
        if (err < 0)
                lar_signal_goaway(0);    /* clean&die */

        openlog(name_s, LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "%s %s", desc_s, version_s);

        if (nodaemon == 0)
                daemon(0, 0);

        /* log our pid for scripts. */
        logpid(_PATH_LARDPID);

        /* setup signal handling */
        sig_init();

        err = load_config(lar_config_info);
        if(err < 0)
                lar_signal_goaway(0);    /* clean&die */

	/* init our user viewable entity table. */
	lar_utable_open();
	
        /* we do the real work now, looping and directing. */
	lar_timer_start_garbage();
        err = lar_director();
        return err;
}
