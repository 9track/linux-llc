/* dlswd.c: Data Link Switching Daemon.
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
#include <dlfcn.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/types.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>

/* required for llc sockets. */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/llc.h>

/* our stuff. */
#include <dlsw_ssp.h>
#include <dlsw_vector.h>
#include <dlsw_list.h>
#include <dlsw_timer.h>
#include <dlswd_load.h>
#include <dlswd.h>

#ifndef AF_LLC
#define AF_LLC	26
#define PF_LLC	AF_LLC
#endif

char version_s[]			= VERSION;
char name_s[] 	 			= "dlswd";
char desc_s[] 	 			= "Data link switching daemon";
char maintainer_s[] 			= "Jay Schulist <jschlst@samba.org>";
char web_s[]				= "http://www.linux-sna.org";

int dlsw_ifr_fd = -1;
fd_set dlsw_all_fds;

char config_file[300] 			= _PATH_DLSWDCONF;
global *dlsw_config_info 		= NULL;
struct dlsw_statistics *dlsw_stats 	= NULL;
static list_head(dlsw_partner_list);
static list_head(dlsw_listen_list);

static sigset_t blockmask, emptymask;
static int blocked = 0;

extern void sig_block(void);
extern void sig_unblock(void);

static int dlsw_partner_connect_start(struct dlsw_partner_info *part);

static void dlsw_count_and_set_fds(int fd, fd_set *all_fds)
{
	dlsw_stats->open_fds++;
	if (dlsw_stats->open_fds > dlsw_stats->wmark_fd)
		dlsw_stats->wmark_fd = dlsw_stats->open_fds;
        FD_SET(fd, all_fds);
        if (fd > dlsw_stats->highest_fd)
                dlsw_stats->highest_fd = fd;
	return;
}

static void dlsw_count_and_clear_fds(int fd, fd_set *all_fds)
{
	dlsw_stats->open_fds--;
        FD_CLR(fd, all_fds);
	return;
}

static dlsw_partner_t *dlsw_partner_find_by_read_fd(int fd)
{
	dlsw_partner_t *l = NULL;
        struct list_head *le;

        list_for_each(le, &dlsw_partner_list) {
                l = list_entry(le, dlsw_partner_t, list);
                if(l->read_fd == fd)
                        goto out;
                else
                        l = NULL;
        }
out:    return l;
} 

static dlsw_partner_t *dlsw_partner_find_by_ip(u_int32_t ip)
{
	dlsw_partner_t *l = NULL;
        struct list_head *le;

        list_for_each(le, &dlsw_partner_list) {
                l = list_entry(le, dlsw_partner_t, list);
                if(l->ip.s_addr == ip)
                        goto out;
                else
                        l = NULL;
        }
out:    return l;
}

static int dlsw_partner_delete_list(void)
{
        struct list_head *le, *se;
        dlsw_partner_t *l;

        list_for_each_safe(le, se, &dlsw_partner_list) {
                l = list_entry(le, dlsw_partner_t, list);
                list_del((struct list_head *)l);
                free(l);
        }
        return 0;
}

static int dlsw_partner_delete(dlsw_partner_t *prtnr)
{
        struct list_head *le, *se;
        dlsw_partner_t *l = NULL;

        list_for_each_safe(le, se, &dlsw_partner_list) {
                l = list_entry(le, dlsw_partner_t, list);
                if (prtnr->ip.s_addr == l->ip.s_addr) {
                        list_del((struct list_head *)l);
                        free(l);
                        return 0;
                }
        }
        return -ENOENT;
}

static struct dlsw_listen *dlsw_listen_find_by_fd(int fd)
{
        struct dlsw_listen *l = NULL;
        struct list_head *le;

        list_for_each(le, &dlsw_listen_list) {
                l = list_entry(le, struct dlsw_listen, list);
                if (l->listen_fd == fd)
                        goto out;
                else
                        l = NULL;
        }
out:    return l;
}

static int dlsw_listen_delete_list(void)
{
        struct list_head *le, *se;
        struct dlsw_listen *l;

        list_for_each_safe(le, se, &dlsw_listen_list) {
                l = list_entry(le, struct dlsw_listen, list);
                list_del((struct list_head *)l);
                free(l);
        }
        return 0;
}

static int dlsw_listen_delete_info_list(void)
{
	struct list_head *le, *se;
	struct dlsw_listen_info *l;

	list_for_each_safe(le, se, &dlsw_config_info->listen_list) {
		l = list_entry(le, struct dlsw_listen_info, list);
		list_del((struct list_head *)l);
		free(l);
	}
        return 0;
}

static int dlsw_partner_delete_info_list(void)
{
	struct list_head *le, *se;
	struct dlsw_partner_info *l;

	list_for_each_safe(le, se, &dlsw_config_info->partner_list) {
		l = list_entry(le, struct dlsw_partner_info, list);
		list_del((struct list_head *)l);
		free(l);
	}
	return 0;
}

static int dlsw_partner_tx_data(dlsw_partner_t *to, void *data, int len)
{
	return send(to->write_fd, data, len, 0);
}

static int dlsw_cap_xchng_tx_rsp(dlsw_partner_t *partner, void *data, int len)
{
	ssp_ctrl_t *ssp;
	int txlen, err;

	txlen = sizeof(ssp_ctrl_t) + len;
	ssp = new_s(txlen);
	if (!ssp)
		return -ENOMEM;
	ssp->version    = partner->version.version;
        ssp->hdrlen     = SSP_HDRLEN_CTRL;
        ssp->msglen     = htons(len);
        ssp->msgtype    = SSP_MSG_CAP_EXCHANGE;
        ssp->proto      = SSP_PROTO_ID;
        ssp->hdrnum     = 0x01;
        ssp->oldmsgtype = SSP_MSG_CAP_EXCHANGE;
        ssp->fdir       = SSP_DIR_RSP;
        memcpy(ssp->data, data, len);
        err = dlsw_partner_tx_data(partner, ssp, txlen);
        if (err < 0)
	         printf("%s: partner_tx_data error `%s'.\n", __FUNCTION__,
                         strerror(errno));
        free(ssp);
	return err;
}

static int dlsw_cap_xchng_init(dlsw_partner_t *local, dlsw_partner_t *remote)
{
	int len, err, saved_mvlen;
	major_vector_t *mv;
        ssp_ctrl_t *ssp;
	
	if (!local->saved_capXchng)
		return -EINVAL;
	mv = dlsw_vect_tx_cap_xchng_c(local->saved_capXchng);
	if (!mv)
		return -EINVAL;
	saved_mvlen = mv->len;
	mv->len = htons(saved_mvlen);
	
	len = sizeof(ssp_ctrl_t) + saved_mvlen;
	ssp = new_s(len);
	if (!ssp) {
		free(mv);
		return -ENOMEM;
	}
	ssp->version	= local->version.version;
	ssp->hdrlen	= SSP_HDRLEN_CTRL;
	ssp->msglen	= mv->len;
	ssp->msgtype	= SSP_MSG_CAP_EXCHANGE;
	ssp->proto	= SSP_PROTO_ID;
	ssp->hdrnum	= 0x01;
	ssp->oldmsgtype = SSP_MSG_CAP_EXCHANGE;
	ssp->fdir	= SSP_DIR_REQ;
	memcpy(ssp->data, mv, saved_mvlen);
	err = dlsw_partner_tx_data(remote, ssp, len);
	if (err < 0)
		printf("%s: partner_tx_data error `%s'.\n", __FUNCTION__,
			strerror(errno));
	free(ssp);
	free(mv);
	return err;
}

static int dlsw_cap_xchng_ctrl_chk(dlsw_version_t *ver, ssp_ctrl_t *info)
{
	if (info->version > ver->version) {
		printf("%s: incompatible version (%02X > %02X)\n", __FUNCTION__,
			info->version, ver->version);
		return -EINVAL;
	}
	if (info->hdrlen != SSP_HDRLEN_CTRL) {
		printf("%s: bad hdrlen (%d)\n", __FUNCTION__, info->hdrlen);
		return -EINVAL;
	}
	if (info->msgtype != SSP_MSG_CAP_EXCHANGE) {
		printf("%s: bad msgtype (%02X)\n", __FUNCTION__, info->msgtype);
		return -EINVAL;
	}
	if (info->proto != SSP_PROTO_ID) {
		printf("%s: bad proto (%02X)\n", __FUNCTION__, info->proto);
		return -EINVAL;
	}
	if (info->hdrnum != SSP_HDRNUM) {
		printf("%s: bad hdrnum (%d)\n", __FUNCTION__, info->hdrnum);
		return -EINVAL;
	}
	if (info->oldmsgtype != SSP_MSG_CAP_EXCHANGE) {
                printf("%s: bad oldmsgtype (%02X)\n", __FUNCTION__, info->oldmsgtype);
                return -EINVAL;
        }
	if (info->fdir > SSP_DIR_RSP) {
		printf("%s: bad frame direction (%02X)\n", __FUNCTION__,
			info->fdir);
		return -EINVAL;
	}
	return 0;
}

static int dlsw_cap_xchng_chk_comp(ssp_ctrl_t *info, 
	dlsw_cap_cmd_pkt_t *cap_c, dlsw_partner_t *partner)
{
	printf("%s: using lazy capabilities checking, fixme.\n", name_s);
	return 0;
}

static int dlsw_process_msg_cap_exchange(dlsw_partner_t *partner,
	ssp_ctrl_t *info)
{
	dlsw_cap_cmd_pkt_t *cap_c;
	dlsw_cap_rsp_pkt_t *cap_r;
	major_vector_t *mv;
	int err, i;

	/* check ssp control header. */
	err = dlsw_cap_xchng_ctrl_chk(&partner->version, info);
	if (err < 0) {
		printf("%s: invalid ctrl header.\n", __FUNCTION__);
		return err;
	}
	
	mv = (major_vector_t *)info->data;
	switch (ntohs(mv->id)) {
		case DLSW_MV_CAP_XCHNG_CMD:
			if (!new(cap_c))
				return -ENOMEM;
			err = dlsw_sub_vector_parse(mv, 
				dlsw_vect_rx_cap_xchng_c, cap_c);
			if (err < 0) {
				free(cap_c);
				return err;
			}
			
			/* check to see if capXchng values compatible. */
			err = dlsw_cap_xchng_chk_comp(info, cap_c, partner);
			if (err < 0) {
				printf("%s: partner %s has invalid capabilities.\n",
					name_s, inet_ntoa(partner->ip));
				free(cap_c);
				return err;
			}

			/* valid caps, save xchng and ack. */
			partner->saved_capXchng = cap_c;
			mv = dlsw_vect_tx_cap_xchng_pos_r();
			err = dlsw_cap_xchng_tx_rsp(partner, mv, mv->len);
			if (err < 0) {
				printf("%s: cap_xchng pos rsp error\n", __FUNCTION__);
				free(mv);
				return err;
			}
			free(mv);
			break;
			
		case DLSW_MV_CAP_XCHNG_POS_RSP:
			partner->flags &= ~DLSW_PARTNER_INACTIVE;
                        partner->flags |= DLSW_PARTNER_ACTIVE;
			printf("%s: partner %s set SSP communication active.\n",
				name_s, inet_ntoa(partner->ip));
			break;
			
		case DLSW_MV_CAP_XCHNG_NEG_RSP:
			if (!new(cap_r))
				return -ENOMEM;
			err = dlsw_vect_rx_cap_xchng_r(mv, DLSW_MV_DATA(mv), cap_r);
			if (err < 0) {
				free(cap_r);
				return err;
			}
			for (i = 0; cap_r->code[i] != NULL; i++) {
				printf("%s: partner %s error @ offset=%04X for reason=%04X\n",
					name_s, inet_ntoa(partner->ip),
					cap_r->code[i]->offset,
					cap_r->code[i]->reason);
			}
			printf("%s: partner %s indicated non-compatible.\n",
				name_s, inet_ntoa(partner->ip));
			close(partner->write_fd);
			partner->write_fd = 0;
			break;
			
		default:
			printf("%s: unknown cap_exchange mv %02X\n", __FUNCTION__,
				ntohs(mv->id));
			return -EINVAL;
	}
	return 0;
}

static int dlsw_partner_read_accept(dlsw_partner_t *local)
{
        struct sockaddr_in from, to;
        int fromlen = sizeof(from);
        dlsw_partner_t *partner;
        int partner_fd, err = 0;
			        
        memset(&from, 0, sizeof(from));
        partner_fd = accept(local->read_fd, (struct sockaddr *)&from, &fromlen);
        if (partner_fd < 0)
                return partner_fd;
        partner = dlsw_partner_find_by_ip(from.sin_addr.s_addr);
        if (!partner) {
                printf("%s: unknown partner %s attempted connection.\n", name_s,
	                inet_ntoa(from.sin_addr));
                close(partner_fd);
                return -ENOENT;
        }       
        if (!(partner->flags & DLSW_PARTNER_INBOUND)) {
                printf("%s: partner %s is not allowed inbound connection.\n", name_s,
	                inet_ntoa(from.sin_addr));
                close(partner_fd);
                return -EACCES;
        }
        printf("%s: incomming partner %s accepted on read port (%d).\n",
                name_s, inet_ntoa(partner->ip), local->read_port);

        /* start capXchange. */
        err = dlsw_cap_xchng_init(local, partner);
        if (err < 0) {
		printf("%s: initial cap exchange tx failed, partner %d dropped.\n",
			name_s, inet_ntoa(partner->ip));
                close(partner_fd);
		goto out;
        }
	partner->read_fd = partner_fd;
        dlsw_count_and_set_fds(partner->read_fd, &dlsw_all_fds);
out:    return 0;
}

static int dlsw_process_partner_read_data(dlsw_partner_t *partner)
{
	int rxlen, pktlen = 8192;
	ssp_info_t *info;
	u_int8_t *pkt;

	pkt = new_s(pktlen);
	if (!pkt)
		return -ENOMEM;

	/* process user request. */
        rxlen = recv(partner->read_fd, pkt, pktlen, 0);
        if (rxlen < 0 || rxlen == 0) {
		/* tear down entire dlsw partner. */
		printf("%s: disconnect\n", __FUNCTION__);
	        free(pkt);
	        return 0;
	}
	if (rxlen < sizeof(ssp_info_t)) {
	        free(pkt);
	        return -EINVAL;
	}

	info = (ssp_info_t *)pkt;
	switch (info->msgtype) {
		case SSP_MSG_CANUREACH:
			printf("%s: SSP_MSG_CANUREACH\n", __FUNCTION__);
			break;
		
		case SSP_MSG_ICANREACH:
			printf("%s: SSP_MSG_ICANREACH\n", __FUNCTION__);
			break;

		case SSP_MSG_REACH_ACK:
			printf("%s: SSP_MSG_REACH_ACK\n", __FUNCTION__);
			break;

		case SSP_MSG_DGRMFRAME:
			printf("%s: SSP_MSG_DGRMFRAME\n", __FUNCTION__);
			break;

		case SSP_MSG_XIDFRAME:
			printf("%s: SSP_MSG_XIDFRAME\n", __FUNCTION__);
			break;

		case SSP_MSG_CONTACT:
			printf("%s: SSP_MSG_CONTACT\n", __FUNCTION__);
			break;

		case SSP_MSG_CONTACTED:
			printf("%s: SSP_MSG_CONTACTED\n", __FUNCTION__);
			break;

		case SSP_MSG_RESTART_DL:
			printf("%s: SSP_MSG_RESTART_DL\n", __FUNCTION__);
			break;

		case SSP_MSG_DL_RESTARTED:
			printf("%s: SSP_MSG_DL_RESTARTED\n", __FUNCTION__);
			break;

		case SSP_MSG_ENTER_BUSY:
			printf("%s: SSP_MSG_ENTER_BUSY\n", __FUNCTION__);
			break;

		case SSP_MSG_EXIT_BUSY:
			printf("%s: SSP_MSG_EXIT_BUSY\n", __FUNCTION__);
			break;

		case SSP_MSG_INFOFRAME:
			printf("%s: SSP_MSG_INFOFRAME\n", __FUNCTION__);
			break;

		case SSP_MSG_HALT_DL:
			printf("%s: SSP_MSG_HALT_DL\n", __FUNCTION__);
			break;

		case SSP_MSG_DL_HALTED:
			printf("%s: SSP_MSG_DL_HALTED\n", __FUNCTION__);
			break;

		case SSP_MSG_NETBIOS_NQ:
			printf("%s: SSP_MSG_NETBIOS_NQ\n", __FUNCTION__);
			break;

		case SSP_MSG_NETBIOS_NR:
			printf("%s: SSP_MSG_NETBIOS_NR\n", __FUNCTION__);
			break;

		case SSP_MSG_DATAFRAME:
			printf("%s: SSP_MSG_DATAFRAME\n", __FUNCTION__);
			break;

		case SSP_MSG_HALT_DL_NOACK:
			printf("%s: SSP_MSG_HALT_DL_NOACK\n", __FUNCTION__);
			break;

		case SSP_MSG_NETBIOS_ANQ:
			printf("%s: SSP_MSG_NETBIOS_ANQ\n", __FUNCTION__);
			break;

		case SSP_MSG_NETBIOS_ANR:
			printf("%s: SSP_MSG_NETBIOS_ANR\n", __FUNCTION__);
			break;

		case SSP_MSG_KEEPALIVE:
			printf("%s: SSP_MSG_KEEPALIVE\n", __FUNCTION__);
			break;

		case SSP_MSG_CAP_EXCHANGE:
			dlsw_process_msg_cap_exchange(partner, (ssp_ctrl_t *)pkt);
			break;

		case SSP_MSG_IFCM:
			printf("%s: SSP_MSG_IFCM\n", __FUNCTION__);
			break;

		case SSP_MSG_TEST_CIRCUIT_REQ:
			printf("%s: SSP_MSG_TEST_CIRCUIT_REQ\n", __FUNCTION__);
			break;

		case SSP_MSG_TEST_CIRCUIT_RSP:
			printf("%s: SSP_MSG_TEST_CIRCUIT_RSP\n", __FUNCTION__);
			break;

		default:
			printf("%s: unknown SSP msgtype 0x%02X\n", __FUNCTION__,
				info->msgtype);
			break;
	}
	free(pkt);
	return 0;
}

static int dlsw_process_partner_read_event(dlsw_partner_t *partner)
{
        /* accept new partner. */
        if (partner->flags & DLSW_PARTNER_LOCAL) {
                dlsw_partner_read_accept(partner);
                return 0;
        }
        dlsw_process_partner_read_data(partner);
        return 0;
}

static int dlsw_partner_inbound_init(struct dlsw_partner_info *part)
{
	dlsw_partner_t *remote;
	int err;

	if (!new(remote))
		return -ENOMEM;
	list_init_head(&remote->circuit_list);
        list_init_head(&remote->lhw_mac_list);
	remote->version.version = part->version;
        remote->write_port      = part->write_port;
        remote->read_port       = part->read_port;
        remote->flags           = (DLSW_PARTNER_INACTIVE | DLSW_PARTNER_STATIC
		| DLSW_PARTNER_INBOUND);
        memcpy(&remote->ip, &part->ip, sizeof(struct in_addr));
        list_add_tail(&remote->list, &dlsw_partner_list);
        printf("%s: partner %s@%d allowed inbound access.", name_s, 
		inet_ntoa(remote->ip), remote->read_port);
	return 0;
}

void dlsw_partner_connect(void *data)
{
	struct dlsw_partner_info *part = data;
	struct sockaddr_in sin;
	dlsw_partner_t *remote;
	int fd, err = 0;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		goto error;

	memset(&sin, 0, sizeof(sin));
        sin.sin_family  = PF_INET;
        sin.sin_port    = htons(part->write_port);
        sin.sin_addr.s_addr = INADDR_ANY;
        err = bind(fd, (struct sockaddr *)&sin, sizeof(sin));
        if (err < 0)
                goto error;
	
	memset(&sin, 0, sizeof(sin));
	sin.sin_family		= PF_INET,
	sin.sin_port		= htons(part->read_port);
	memcpy(&sin.sin_addr, &part->ip, sizeof(struct in_addr));
	err = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
	if (err < 0) {
		printf("%s: connect failed `%s'.\n", name_s, strerror(errno));
		close(fd);
		goto error;
	}
	
	if (!new(remote)) {
		close (fd);
		goto error;
	}
	list_init_head(&remote->circuit_list);
	list_init_head(&remote->lhw_mac_list);
	remote->version.version	= part->version;
	remote->write_fd	= fd;
	remote->write_port	= part->write_port;
	remote->read_fd		= 0;
	remote->read_port	= part->read_port;
	remote->flags		= (DLSW_PARTNER_INACTIVE | DLSW_PARTNER_STATIC
		| DLSW_PARTNER_OUTBOUND | DLSW_PARTNER_INBOUND);
	memcpy(&remote->ip, &part->ip, sizeof(struct in_addr));
	dlsw_count_and_set_fds(remote->read_fd, &dlsw_all_fds);
	list_add_tail(&remote->list, &dlsw_partner_list);
	printf("%s: partner %s@%d connected.\n", name_s, inet_ntoa(remote->ip), 
		remote->read_port);
	goto out;

error:	dlsw_partner_connect_start(part);
	part->connect_tries++;
	printf("%s: partner %s connect failed (%d).\n", name_s,
		inet_ntoa(remote->ip), part->connect_tries);
out:	return;
}

static int dlsw_partner_connect_start(struct dlsw_partner_info *part)
{
	timer_start(1, DLSW_PARTNER_CONNECT_TIMEOUT * 1000,
		dlsw_partner_connect, (void *)part);
	return 0;
}

static int dlsw_partner_connect_stop(void)
{
	return 0;
}

static int dlsw_user_table_check(void)
{
	struct list_head *ent;
        int blen = 8192;
        int fd, len = 0;
        char *buf;

        fd = open(_PATH_DLSW_USER_TABLE, O_WRONLY | O_NONBLOCK, 0);
        if (fd < 0)
                return fd;
        buf = new_s(blen);
        if (!blen)
                return -ENOMEM;
        len += sprintf(buf + len, "partner           ver flags status write_port read_port write_fd read_fd\n");
	list_for_each(ent, &dlsw_partner_list) {
		dlsw_partner_t *p = list_entry(ent, dlsw_partner_t, list);
		if (blen - len < 1000) {
			buf = realloc(buf, blen * 2);
	                blen = blen * 2;
	        }

		len += sprintf(buf + len, "%-17s %-3d %04X  %04X   %-10d %-9d %-8d %-7d\n", 
			inet_ntoa(p->ip), p->version, p->flags, p->status,
			p->write_port, p->read_port, p->write_fd, p->read_fd);
	}
	
	/* write the buffer to user. */
        write(fd, buf, len);
        free(buf);
        close(fd);
        usleep(1000);
        return 0;
}


/* user wants us dead, so lets cleanup and die. */
void dlsw_signal_goaway(int signum)
{
	struct list_head *ent;

        (void)signum;

	list_for_each(ent, &dlsw_partner_list) {
		dlsw_partner_t *part = list_entry(ent, dlsw_partner_t, list);
		if (part->read_fd)
			close(part->read_fd);
		if (part->write_fd)
			close(part->write_fd);
	}
	
	if (dlsw_config_info) {
		dlsw_listen_delete_info_list();
		dlsw_partner_delete_info_list();
		free(dlsw_config_info);
	}

	if(dlsw_ifr_fd)
		close(dlsw_ifr_fd);

	syslog(LOG_ERR, "Structured tear-down complete (%d).", 
		dlsw_stats->open_fds);
	free(dlsw_stats);

        unlink(_PATH_DLSWDPID);
	unlink(_PATH_DLSW_USER_TABLE);
        closelog();
        exit (0);
}

static int dlsw_director(void)
{
	dlsw_partner_t *partner;
	struct timeval timeout;
	fd_set readable;
	int fd, i;

        syslog(LOG_INFO, "Director activated.\n");

	sig_block();
        for (;;) {
		readable = dlsw_all_fds;

		memset(&timeout, 0, sizeof(timeout));
                timeout.tv_usec = DLSW_DIR_TIMEOUT;
		
		sig_unblock();
		fd = select(dlsw_stats->highest_fd + 1, &readable, 
			NULL, NULL, &timeout);
		sig_block();

		if (fd == 0) {
			dlsw_user_table_check();
			continue;
		}
		
		dlsw_stats->director_events++;
		if (fd < 0) {	/* check for immediate errors. */
			if (fd < 0 && errno != EINTR) {
                                syslog(LOG_ERR, "select failed: %s",
					strerror(errno));
                                sleep(1);
                        }
			dlsw_stats->director_errors++;
                        continue;
		}

		/* find which fd has an event for us. */
		for (i = 3; i <= dlsw_stats->highest_fd; i++) {
                        if (FD_ISSET(i, &readable)) {
				partner = dlsw_partner_find_by_read_fd(i);
				if (partner) {
					/* process partner data. */
					dlsw_process_partner_read_event(partner);
					continue;
				}
				
				/* now we do something useful. */
				printf("%s: unknown file descriptor event (%d)\n", name_s, i);
                        }
                }
	}
        return 0;
}

static int dlsw_dev_get_ifindex(char *ifname)
{
        struct ifreq ifr;
        int err;

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, ifname);
        err = ioctl(dlsw_ifr_fd, SIOCGIFINDEX, &ifr);
        if (err < 0)
                return err;
        return ifr.ifr_ifindex;
}

static int dlsw_dev_get_ifmac(char *ifname, char *ifmac)
{
        struct ifreq ifr;
        int err;

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, ifname);
        err = ioctl(dlsw_ifr_fd, SIOCGIFHWADDR, &ifr);
        if (err < 0)
                return err;
        memcpy(ifmac, (char *)&ifr.ifr_hwaddr.sa_data,
                IFHWADDRLEN);
        return 0;
}

int dlsw_load_listen(struct dlsw_listen_info *listen)
{
	struct dlsw_listen *lstn;
	int index, fd, err;
	u_int8_t *sap;
	int i;
	
        /* setup the physical interface. */
        index = dlsw_dev_get_ifindex(listen->ifname);
        if (index < 0) {
		printf("%s: ifindex failed for %s `%s'.\n", name_s,
		        listen->ifname, strerror(index));
                return index;
        }
        listen->ifindex = index;
        err = dlsw_dev_get_ifmac(listen->ifname, listen->ifmac);
        if (err < 0) {
                printf("%s: ifmac failed `%s'.\n", name_s, strerror(err));
                return err;
        }

	/* allocate the listen information. */
        if(!new(lstn)) {
                return -ENOMEM;
        }
        lstn->listen_fd 		= 0;
        lstn->ifindex   		= listen->ifindex;
	lstn->sna			= listen->sna;
	lstn->netbios			= listen->netbios;
	lstn->mac_addr_exclusive	= listen->mac_exclusive;
	lstn->netbios_exclusive		= listen->netbios_exclusive;
	for (i = 0; listen->sna_sap_list[i] != NULL; i++);
	lstn->sna_sap_list = new_s(sizeof(u_int8_t) * (i + 1));
	for (i = 0; listen->sna_sap_list[i] != NULL; i++) {
		lstn->sna_sap_list[i] = new_s(sizeof(u_int8_t));
		lstn->sna_sap_list[i] = listen->sna_sap_list[i];
	}
	lstn->sna_sap_list[i] = NULL;
	for (i = 0; listen->netbios_sap_list[i] != NULL; i++);
        lstn->netbios_sap_list = new_s(sizeof(u_int8_t) * (i + 1));
        for (i = 0; listen->netbios_sap_list[i] != NULL; i++) {
                lstn->netbios_sap_list[i] = new_s(sizeof(u_int8_t));
                lstn->netbios_sap_list[i] = listen->netbios_sap_list[i];
        }
        lstn->netbios_sap_list[i] = NULL;
        memcpy(&lstn->ifname, &listen->ifname, IFNAMSIZ);
        memcpy(&lstn->ifmac, &listen->ifmac, IFHWADDRLEN);
        list_add_tail(&lstn->list, &dlsw_listen_list);
	return 0;
}

int dlsw_load_partner(struct dlsw_partner_info *partner)
{
	if (partner->direction)
		dlsw_partner_connect(partner);
	else 
		dlsw_partner_inbound_init(partner);
	return 0;
}

int dlsw_load_user_table(void)
{
	int err;
        unlink(_PATH_DLSW_USER_TABLE);
        err = mkfifo(_PATH_DLSW_USER_TABLE,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if(err < 0 && errno != EEXIST)
                return err;
        return 0;
}

char *dlsw_print_sap_bitmap(u_int8_t *sl)
{
        int i, c, lsb, blen = 0;
        static u_int8_t buf[1500];
        u_int8_t lsap;

        for (i = 0; i < 16; i++) {
                if (!sl[i])
                        continue;
                for (lsb = 0, c = 0xE; c >= 0x0; lsb++, c -= 0x2) {
                        if ((sl[i] >> lsb) & 0x01) {
                                lsap  = i << 4;
                                lsap |= c;
                                blen += sprintf(buf + blen, "0x%02X ", lsap);
                        }
                }
		blen += sprintf(buf + blen, "\n");
        }
        return buf;
}

static int dlsw_set_sap_bitmap(u_int8_t *sl, u_int8_t sap)
{
        int msb, lsb, i;
        msb = ((sap & 0xF0) >> 4);
        for (lsb = 0, i = 0xE; i >= 0x0; lsb++, i -= 0x2) {
                if (i != (sap & 0x0F))
			continue;
                sl[msb] |= 1 << lsb;
		break;
        }
        return 0;
}

int dlsw_load_local_ssp(struct dlsw_ssp_info *ssp)
{
	struct list_head *ent;
	struct sockaddr_in sin;
	dlsw_partner_t *local;
	dlsw_cap_cmd_pkt_t *capb;
	int err;

	if (!new(local))
		return -ENOMEM;
	list_init_head(&local->circuit_list);
	list_init_head(&local->lhw_mac_list);
	local->write_port 	= ssp->write_port;
	local->read_port	= ssp->read_port;
	local->flags 		= (DLSW_PARTNER_ACTIVE 
		| DLSW_PARTNER_LOCAL | DLSW_PARTNER_STATIC);
	local->version.version 	= ssp->version;
	local->tcp_conn		= ssp->tcpconn;
	local->pacing_window	= ssp->window;
	memcpy(local->version_string, dlsw_stats->version_string, 
		sizeof(dlsw_vstring_t));
	memcpy(local->vendor_context, dlsw_stats->vendor_context, 
		sizeof(dlsw_oui_t));
	memcpy(local->vendor_id, dlsw_stats->vendor_id, sizeof(dlsw_oui_t));
	err = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (err < 0) {
		free(local);
		return err;
	}
	local->read_fd = err;
	
	/* bind. */
	memset(&sin, 0, sizeof(sin));
        sin.sin_family  = PF_INET;
        sin.sin_port    = htons(local->read_port);
        sin.sin_addr.s_addr = INADDR_ANY;
	err = bind(local->read_fd, (struct sockaddr *)&sin, sizeof(sin));
        if (err < 0)
		goto error;

	/* listen. */
	err = listen(local->read_fd, SSP_READ_PORT_BACKLOG);
	if (err < 0)
		goto error;

	/* build and store default capabilities. */
	if (!new(capb)) {
		close(local->read_fd);
		free(local);
		return -ENOMEM;
	}
	/* vendor id. */
	capb->vfield |= DLSW_CAP_VFIELD_VENDOR_ID;
	memcpy(capb->vendor_id, local->vendor_id, sizeof(dlsw_oui_t));

	/* version. */
	capb->vfield |= DLSW_CAP_VFIELD_VERSION;
	memcpy(&capb->version, &local->version, sizeof(dlsw_version_t));

	/* version string. */
	capb->vfield |= DLSW_CAP_VFIELD_VERSION_STRING;
	memcpy(capb->version_string, local->version_string, 
		sizeof(dlsw_vstring_t));

	/* vendor context. */
	capb->vfield |= DLSW_CAP_VFIELD_VENDOR_CONTEXT;
	memcpy(capb->vendor_context, local->vendor_context, sizeof(dlsw_oui_t));

	/* tcp connection. */
	capb->vfield |= DLSW_CAP_VFIELD_TCP_CONN;
	capb->tcp_conn 			= local->tcp_conn;

	/* pacing window. */
	capb->vfield |= DLSW_CAP_VFIELD_PACE_WIN;
	capb->pace_win 			= local->pacing_window;

	/* sap list. */
	capb->vfield |= DLSW_CAP_VFIELD_SAP_LIST;
	list_for_each(ent, &dlsw_listen_list) {
		struct dlsw_listen *lstn = list_entry(ent, struct dlsw_listen, list);
		int i;
		for (i = 0; lstn->sna_sap_list[i] != NULL; i++) {
			dlsw_set_sap_bitmap((u_int8_t *)&capb->sap_list,
				lstn->sna_sap_list[i]);
		}
		for (i = 0; lstn->netbios_sap_list[i] != NULL; i++) {
			dlsw_set_sap_bitmap((u_int8_t *)&capb->sap_list,
				lstn->sna_sap_list[i]);
		}
		if (lstn->netbios_exclusive)
			capb->netbios_name_exclsv = lstn->netbios_exclusive;
		if (lstn->mac_addr_exclusive)
			capb->mac_addr_exclsv = lstn->mac_addr_exclusive;
	}

#ifdef NOT      
        /* netbios name list is exclusive. */
        capb->vfield |= DLSW_CAP_VFIELD_NETBIOS_NAME_EXCLSV;
        capb->netbios_name_exclsv       = 0;

        /* mac address list is exclusive. */
        capb->vfield |= DLSW_CAP_VFIELD_MAC_ADDR_EXCLSV;
        capb->mac_addr_exclsv           = 0;

	/* mac address list. */

	/* netbios name list. */
#endif
	local->saved_capXchng	= capb;
	
	dlsw_count_and_set_fds(local->read_fd, &dlsw_all_fds);
	list_add_tail(&local->list, &dlsw_partner_list);
	return 0;

error:  close(local->read_fd);
        return err;
}

void dlsw_signal_retry(int signum)
{
        (void)signum;
        return;
}

void dlsw_signal_flush(int signum)
{
        (void)signum;
        return;
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
        sa.sa_handler = dlsw_signal_flush;
        sigaction(SIGHUP, &sa, NULL);
        sa.sa_handler = dlsw_signal_goaway;
        sigaction(SIGTERM, &sa, NULL);
        sa.sa_handler = dlsw_signal_goaway;
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
void version(void)
{
        printf("%s: %s %s\n%s\n", name_s, desc_s, version_s,
                maintainer_s);
	printf("%s\n", web_s);
        exit(1);
}

void help(void)
{
        printf("Usage: %s [-h] [-V] [-d level] [-f config]\n", name_s);
        exit(1);
}

int main(int argc, char **argv)
{
        int nodaemon = 0, err, c;
	char vs[40], vid[3];
	
	if (!new(dlsw_stats))
		return -ENOMEM;
	FD_ZERO(&dlsw_all_fds);
	while ((c = getopt(argc, argv, "hvVf:d:")) != EOF) {
                switch (c) {
                        case 'd':       /* don't go into background. */
                                dlsw_stats->debug = nodaemon = atoi(optarg);
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

	dlsw_ifr_fd = socket(PF_INET, SOCK_DGRAM, 0);
        if (dlsw_ifr_fd < 0) {
		printf("%s: utility socket failed `%s'.\n", name_s, strerror(errno));
                dlsw_signal_goaway(0);
	}

	err = load_config_file(config_file);
        if (err < 0) {
		printf("%s: configuration file load failed `%s'.\n", name_s, strerror(errno));
        	dlsw_signal_goaway(0);    /* clean&die */
	}

        openlog(name_s, LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "%s %s", desc_s, version_s);

        if (nodaemon == 0)
                daemon(0, 0);

	/* log our pid for scripts. */
	logpid(_PATH_DLSWDPID);

        /* setup signal handling */
        sig_init();

	/* create version/vendor specific data for capXchange. */
	strncpy(dlsw_stats->vendor_id, "LNX", 3);
	strncpy(dlsw_stats->vendor_context, "LNX", 3);
	sprintf(dlsw_stats->version_string, "linux-DLSW");
	
	/* execute loaded configuration information. */
	err = load_config(dlsw_config_info);
        if (err < 0) {
		printf("%s: exectution of configuration information failed `%s'.\n",
			name_s, strerror(errno));
                dlsw_signal_goaway(0);    /* clean&die */
	}

        /* we do the real work now, looping and directing. */
        err = dlsw_director();
	return err;
}
