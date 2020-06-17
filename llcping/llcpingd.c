/* llcpingd.c: Linux LLC Ping Server utility.
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
#include <sys/socket.h>
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
#include "llcpingd.h"
#include "llcpingd_load.h"

#ifndef AF_LLC
#define AF_LLC  	26
#define PF_LLC          AF_LLC
#endif

char version_s[] 			= VERSION;
char name_s[] 				= "llcpingd";
char desc_s[] 				= "IEEE 802.2 llc echo daemon";
char maintainer_s[] 			= "Jay Schulist <jschlst@samba.org>";
char web_s[]			 	= "http://www.linux-sna.org";

fd_set llc_all_fds;
char config_file[300] 			= _PATH_LLCPINGDCONF;
global *llc_config_info 		= NULL;

struct llc_listen *llc_listen_list	= NULL;
struct llc_data *llc_data_list		= NULL;
struct llc_statistics *llc_stats 	= NULL;

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

void llc_count_and_set_fds(int fd, fd_set *all_fds)
{
	llc_stats->open_fds++;
	if(llc_stats->open_fds > llc_stats->wmark_fd)
		llc_stats->wmark_fd = llc_stats->open_fds;
        FD_SET(fd, all_fds);
        if(fd > llc_stats->highest_fd)
                llc_stats->highest_fd = fd;
	return;
}

void llc_count_and_clear_fds(int fd, fd_set *all_fds)
{
	llc_stats->open_fds--;
        FD_CLR(fd, all_fds);
	return;
}

int llc_get_and_set_hwaddr(u_int8_t *name, u_int8_t *hwaddr)
{
	struct ifreq req;
	int fd;

	if(!strcmp(name, "any")) {
		memset(hwaddr, 0, IFHWADDRLEN);
		return (0);
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(fd < 0)
		return (fd);

        memset(&req, 0, sizeof(req));
        req.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        strcpy(req.ifr_name, name);

        if(ioctl(fd, SIOCGIFHWADDR, &req) < 0) {
		close(fd);
                return (-1);
	}

        memcpy(hwaddr, &req.ifr_hwaddr.sa_data, IFHWADDRLEN);
	close(fd);
	return (0);
}

static int llc_mac_null(unsigned char *mac, int len)
{
        unsigned char addrany[IFHWADDRLEN];
        memset(&addrany, 0, IFHWADDRLEN);
        return (!memcmp(addrany, mac, len));
}


/* this is actually the place where we have to work the hardest, sigh. */
int llc_load_listener(struct llc_linfo *l)
{
	struct sockaddr_llc laddr;
	int err, fd;

	if(!l->type || l->type > 2 || !l->lsap)
		return (-EINVAL);

	/* set the mac address if not set by user. */
	if(llc_mac_null(l->ifmac, IFHWADDRLEN)) {
		err = llc_get_and_set_hwaddr(l->ifname, l->ifmac);
		if(err < 0)
			return (err);
	}

	/* fill the our listen sockaddr_llc. */
	memset(&laddr, 0, sizeof(laddr));
	laddr.sllc_family	= PF_LLC;
	laddr.sllc_arphrd	= ARPHRD_ETHER;
	laddr.sllc_sap		= l->lsap; 
	memcpy(&laddr.sllc_mac, l->ifmac, IFHWADDRLEN);

	/* now lets open the socket, bind and start listening. */
	if(l->type == 1)
		fd = socket(PF_LLC, SOCK_DGRAM, 0);
	else
		fd = socket(PF_LLC, SOCK_STREAM, 0);
	if(fd < 0) {
		printf("%s: socket `%s'.\n", name_s, strerror(errno));
                if(errno == EAFNOSUPPORT)
                        printf("%s: did you load the llc module?\n", name_s);
		return (fd);
	}
	err = bind(fd, (struct sockaddr *)&laddr, sizeof(laddr));
	if(err < 0) {
		printf("%s: %s@0x%02X bind failed `%s'.\n",  name_s, 
			pr_ether(l->ifmac), l->lsap, strerror(errno));
		close(fd);
		return (err);
	}

	if(l->type == 1) {
		struct llc_data *data;
		if(!new(data)) {
			close(fd);
			return (-ENOMEM);
		}

		data->type	= l->type;
                data->lsap	= l->lsap;
		data->ifindex	= l->ifindex;
		data->data_fd 	= fd;
		memcpy(&data->data_addr, &laddr, sizeof(laddr));
		memcpy(&data->ifname, &l->ifname, IFNAMSIZ);
		memcpy(&data->ifmac, &l->ifmac, IFHWADDRLEN);
		data->next	= llc_data_list;
		llc_data_list	= data;
	} else {
		struct llc_listen *lstn;
		if(!new(lstn)) {
			close(fd);
			return (-ENOMEM);
		}

		err = listen(fd, 10);
		if(err < 0) {
			close(fd);
			free(lstn);
			return (err);
		}

		lstn->type      = l->type;
                lstn->lsap      = l->lsap;
                lstn->ifindex   = l->ifindex;
		lstn->listen_fd = fd;
		memcpy(&lstn->listen_addr, &laddr, sizeof(laddr));
		memcpy(&lstn->ifname, &l->ifname, IFNAMSIZ);
                memcpy(&lstn->ifmac, &l->ifmac, IFHWADDRLEN);
		lstn->next	= llc_listen_list;
		llc_listen_list	= lstn;
	}

	llc_count_and_set_fds(fd, &llc_all_fds);
	syslog(LOG_ERR, "listen llc%d on %s using %s@0x%02X", 
		l->type, l->ifname, pr_ether(l->ifmac), l->lsap);
	return (0);
}

struct llc_listen *llc_find_listener_by_fd(int fd)
{
	struct llc_listen *l;

	for(l = llc_listen_list; l != NULL; l = l->next)
		if(l->listen_fd == fd)
			return (l);
        return (NULL);
}

struct llc_data *llc_find_data_by_fd(int fd)
{
	struct llc_data *d;

	for(d = llc_data_list; d != NULL; d = d->next)
		if(d->data_fd == fd)
			return (d);
	return (NULL);
}

int llc_delete_data(struct llc_data *data)
{       
        struct llc_data *ent, **clients;
                        
        clients = &llc_data_list;
        while((ent = *clients) != NULL ){
		if(data->data_fd == ent->data_fd) {
                        *clients = ent->next;
                        free(ent);
                        return (0);
                }
                clients = &ent->next;
        }       
        
        return (-ENOENT);
}       

int llc_delete_listen_list(void)
{       
        struct llc_listen *ent1, **clients1;
        
        clients1 = &llc_listen_list;
        while((ent1 = *clients1) != NULL) {
                *clients1 = ent1->next;
                free(ent1);
        }

        return (0);
}

int llc_delete_data_list(void)
{
        struct llc_data *ent1, **clients1;

        clients1 = &llc_data_list;
        while((ent1 = *clients1) != NULL) {
                *clients1 = ent1->next;
                free(ent1);
        }

        return (0);
}

int llc_delete_linfo_list(void)
{
        struct llc_linfo *ent1, **clients1;

        clients1 = &llc_config_info->ll;
        while((ent1 = *clients1) != NULL) {
                *clients1 = ent1->next;
                free(ent1);
        }

        return (0);
}

static int llc_accept_client(struct llc_listen *lstn)
{
	struct sockaddr from;
	int fromlen;
	struct llc_data *data;
	int client_fd;

	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	client_fd = accept(lstn->listen_fd, (struct sockaddr *)&from, &fromlen);
	if(client_fd < 0)
		return (client_fd);

	if(!new(data))
		return (-ENOMEM);
	data->type	= 2;
	data->lsap	= lstn->lsap;
	data->data_fd 	= client_fd;
	memcpy(&data->data_addr, &from, sizeof(from));
	memcpy(data->ifname, lstn->ifname, IFNAMSIZ);
	memcpy(data->ifmac, lstn->ifmac, IFHWADDRLEN);

	syslog(LOG_ERR, "accept:%d llc%d on %s to %02X:%02X:%02X:%02X:%02X:%02X@0x%02X"
		" from %02X:%02X:%02X:%02X:%02X:%02X@0x%02X", data->data_fd,
                data->type, data->ifname, data->ifmac[0], data->ifmac[1], data->ifmac[2],
                data->ifmac[3], data->ifmac[4], data->ifmac[5], data->lsap, 
		data->data_addr.sllc_mac[0], data->data_addr.sllc_mac[1],
		data->data_addr.sllc_mac[2], data->data_addr.sllc_mac[3],
		data->data_addr.sllc_mac[4], data->data_addr.sllc_mac[5],
		data->data_addr.sllc_sap);

	data->next      = llc_data_list;
        llc_data_list   = data;
	llc_count_and_set_fds(client_fd, &llc_all_fds);
	return (0);
}

int hexdump(unsigned char *pkt_data, int pkt_len)
{
        int i;

        while(pkt_len>0) {
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

static int llc_process_data(struct llc_data *data)
{
	struct sockaddr_llc from, to;
	int fromlen;
	u_int8_t *pkt;
	int pktlen = 8192;
	int rxlen;

	pkt = new_s(pktlen);
	if(!pkt)
		return (-ENOMEM);
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	rxlen = recvfrom(data->data_fd, pkt, pktlen, 0, 
		(struct sockaddr *)&from, &fromlen);
	if(rxlen < 0) {
		if(errno == EINTR) {
			free(pkt);
			return (0);
		}

		/* we assume a disconnect. */
		if(data->type == 2) {
			llc_count_and_clear_fds(data->data_fd, &llc_all_fds);
                	close(data->data_fd);

			syslog(LOG_ERR, "disconnect llc%d on %s to %02X:%02X:%02X:%02X:%02X:%02X@0x%02X"
		                " from %02X:%02X:%02X:%02X:%02X:%02X@0x%02X",
		                data->type, data->ifname, data->ifmac[0], data->ifmac[1], data->ifmac[2],
		                data->ifmac[3], data->ifmac[4], data->ifmac[5], data->lsap,
		                data->data_addr.sllc_mac[0], data->data_addr.sllc_mac[1],
		                data->data_addr.sllc_mac[2], data->data_addr.sllc_mac[3],
		                data->data_addr.sllc_mac[4], data->data_addr.sllc_mac[5],
		                data->data_addr.sllc_sap);
			llc_delete_data(data);
			free(pkt);
			return (0);
		}
		free(pkt);
		return (rxlen);
	}

	if(llc_stats->debug >= 5) {
		 printf("RX: SRC:%02X:%02X:%02X:%02X:%02X:%02X @ 0x%02X"
                        " -> DST:%02X:%02X:%02X:%02X:%02X:%02X @ 0x%02X\n",
                        from.sllc_mac[0], from.sllc_mac[1], from.sllc_mac[2],
                        from.sllc_mac[3], from.sllc_mac[4], from.sllc_mac[5],
                        from.sllc_sap,
                        data->ifmac[0], data->ifmac[1], data->ifmac[2],
                        data->ifmac[3], data->ifmac[4], data->ifmac[5],
                        data->lsap);
	}
	if(llc_stats->debug >= 10)
		hexdump(pkt, rxlen);

	memcpy(&to, &from, sizeof(from));
        memcpy(to.sllc_mac, from.sllc_mac, IFHWADDRLEN);
        to.sllc_sap = from.sllc_sap;

	if(llc_stats->debug >= 5) {
		printf("TX: SRC:%02X:%02X:%02X:%02X:%02X:%02X @ 0x%02X"
                        " -> DST:%02X:%02X:%02X:%02X:%02X:%02X @ 0x%02X\n",
                        data->ifmac[0], data->ifmac[1], data->ifmac[2],
                        data->ifmac[3], data->ifmac[4], data->ifmac[5],
                        data->lsap,
                        to.sllc_mac[0], to.sllc_mac[1], to.sllc_mac[2],
                        to.sllc_mac[3], to.sllc_mac[4], to.sllc_mac[5],
                        to.sllc_sap);
	}
	if(llc_stats->debug >= 10)
		hexdump(pkt, rxlen);

        rxlen = sendto(data->data_fd, pkt, rxlen, 0, 
		(struct sockaddr *)&to, sizeof(to));
	free(pkt);
	if(rxlen < 0) {
		printf("%s: sendto failed `%s'.\n", name_s, strerror(errno));
		return (rxlen);
	}
	return (rxlen * 2);
}

static int llc_director(void)
{
	struct llc_listen *lstn;
	struct llc_data *data;
	fd_set readable;
	int fd, i;

        syslog(LOG_INFO, "Director activated.\n");

	sig_block();
        for(;;) {
		readable = llc_all_fds;

		sig_unblock();
		fd = select(llc_stats->highest_fd + 1, &readable, 
			NULL, NULL, NULL);
		sig_block();

		llc_stats->director_events++;
		if(fd < 0) {	/* check for immediate errors. */
			if(fd < 0 && errno != EINTR) {
                                syslog(LOG_ERR, "select failed `%s' sleep",
					strerror(errno));
                                sleep(1);
                        }
			llc_stats->director_errors++;
                        continue;
		}

		/* find which fd has an event for us. */
		for(i = 3; i <= llc_stats->highest_fd; i++) {
                        if(FD_ISSET(i, &readable)) {
				lstn = llc_find_listener_by_fd(i);
				if(lstn) {	/* new connection so accept it. */
					llc_accept_client(lstn);
					continue;
				}

				data = llc_find_data_by_fd(i);
				if(data) { /* have data, deal with it. */
					llc_process_data(data);
					continue;
				}

				/* well if we are here something is wrong. */
				syslog(LOG_ERR, "Unable to find valid record for fd (%d)\n", i);
				llc_stats->director_errors++;
                        }
                }
	}

        return (0);
}

void llc_signal_retry(int signum)
{
        (void)signum;
        return;
}

void llc_signal_reload(int signum)
{
        (void)signum;
        return;
}

void llc_signal_alarm(int signum)
{
        (void)signum;
        return;
}

/* user wants us dead, so lets cleanup and die. */
void llc_signal_goaway(int signum)
{
        struct llc_listen *lstn;
	struct llc_data *data;

        (void)signum;

	for(lstn = llc_listen_list; lstn != NULL; lstn = lstn->next) {
		llc_count_and_clear_fds(lstn->listen_fd, &llc_all_fds);
		close(lstn->listen_fd);
	}
	for(data = llc_data_list; data != NULL; data = data->next) {
		llc_count_and_clear_fds(data->data_fd, &llc_all_fds);
		close(data->data_fd);
	}
	llc_delete_listen_list();
	llc_delete_data_list();
	llc_delete_linfo_list();
        if(llc_config_info)
                free(llc_config_info);

        syslog(LOG_ERR, "Structured tear-down complete (%ld).",
                llc_stats->open_fds);
        free(llc_stats);

        (void)unlink(_PATH_LLCPINGDPID);
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
        sa.sa_handler = llc_signal_alarm;
        sigaction(SIGALRM, &sa, NULL);
        sa.sa_handler = llc_signal_reload;
        sigaction(SIGHUP, &sa, NULL);
        sa.sa_handler = llc_signal_goaway;
        sigaction(SIGTERM, &sa, NULL);
        sa.sa_handler = llc_signal_goaway;
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

static void logpid(char *path)
{
        FILE *fp;

        if((fp = fopen(path, "w")) != NULL) {
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
        printf("Usage: %s [-h] [-v] [-d level] [-f config]\n", name_s);
        exit(1);
}

int main(int argc, char **argv)
{
        int nodaemon = 0, err, c;

	if(!new(llc_stats))
		return (-ENOMEM);
	FD_ZERO(&llc_all_fds);
	while((c = getopt(argc, argv, "hvVf:d:")) != EOF) {
                switch(c) {
                        case 'd':       /* don't go into background. */
                                llc_stats->debug = nodaemon = atoi(optarg);
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

	err = load_config_file(config_file);
        if(err < 0) {
		printf("%s: configuration file error `%d'.\n", name_s, err);
        	llc_signal_goaway(0);    /* clean&die */
	}

        openlog(name_s, LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "%s %s", desc_s, version_s);

        if(nodaemon == 0)
                daemon(0, 0);

	/* log our pid for scripts. */
	logpid(_PATH_LLCPINGDPID);

        /* setup signal handling */
        sig_init();

	err = load_config(llc_config_info);
        if(err < 0) {
		printf("%s: error executing configuration file information `%d'.\n",
			name_s, err);
                llc_signal_goaway(0);    /* clean&die */
	}

        /* we do the real work now, looping and directing. */
        err = llc_director();
	if(err < 0)
		printf("%s: fatal director error `%d'.\n", name_s, err);
	return (err);
}
