/* dlswd.c: Data Link Switching Daemon.
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
#include <dlfcn.h>
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

#include <linux/if.h>
#include <linux/if_arp.h>

#include <dlsw_load.h>
#include <dlswd.h>
#include <dlsw_proto.h>

char version_s[] 	= VERSION;
char name_s[] 	 	= "dlswd";
char desc_s[] 	 	= "DLSw daemon";
char maintainer_s[] 	= "Jay Schulist <jschlst@samba.org>";
char company_s[] 	= "Screaming Daemon, Inc.";

fd_set dlsw_all_fds;
char config_file[300] = _PATH_DLSWDCONF;
int nodaemon = 0, local_read_fd = 0, local_write_fd = 0, accept_fd = 0;
global *dlsw_config_info = NULL;

struct dlsw_statistics *dlsw_stats = NULL;
struct mon_clt *monitor_list = NULL;

static sigset_t blockmask, emptymask;
static int blocked=0;

extern void sig_block(void);
extern void sig_unblock(void);

void dlsw_count_and_set_fds(int fd, fd_set *all_fds)
{
	dlsw_stats->open_fds++;
	if(dlsw_stats->open_fds > dlsw_stats->wmark_fd)
		dlsw_stats->wmark_fd = dlsw_stats->open_fds;
        FD_SET(fd, all_fds);
        if(fd > dlsw_stats->highest_fd)
                dlsw_stats->highest_fd = fd;
	return;
}

void dlsw_count_and_clear_fds(int fd, fd_set *all_fds)
{
	dlsw_stats->open_fds--;
        FD_CLR(fd, all_fds);
	return;
}

int dlsw_delete_monitor_list(void)
{
	struct monitor *ent1, **clients1;
	struct mon_clt *ent2, **clients2;

	clients1 = &dlsw_config_info->m;
        while((ent1 = *clients1) != NULL)
        {
                *clients1 = ent1->next;
                free(ent1);
        }

        clients2 = &monitor_list;
        while((ent2 = *clients2) != NULL)
        {
                *clients2 = ent2->next;
                free(ent2);
        }

        return (-ENOENT);
}

int dlsw_monitor_delete(int fd)
{
	struct mon_clt *ent, **clients;

        clients = &monitor_list;
        while((ent = *clients) != NULL)
        {
                if(fd == ent->fd)
                {
                        *clients = ent->next;
                        free(ent);
                        return (0);
                }
                clients = &ent->next;
        }

	return (-ENOENT);
}

struct mon_clt *dlsw_find_monitor_by_fd(int fd)
{
	struct mon_clt *m;

	for(m = monitor_list; m != NULL; m = m->next)
		if(m->fd == fd)
			return (m);

	return (NULL);
}

int dlsw_load_monitor(struct monitor *m)
{
	struct sockaddr_in lstn_addr;
	struct sockaddr_in *out;
	int fd, err;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0)
	{
		syslog(LOG_ERR, "dlsw_load_monitor socket failed (%s).",
			strerror(errno));
		return (fd);
	}

	memset(&lstn_addr, 0, sizeof(struct sockaddr_in));
        out = &lstn_addr;
        out->sin_family  = AF_INET;
        out->sin_port    = htons(m->port);
	out->sin_addr.s_addr = INADDR_ANY;
	err = bind(fd, (struct sockaddr *)&lstn_addr, sizeof(lstn_addr));
	if(err < 0)
	{
		syslog(LOG_ERR, "dlsw_load_monitor bind failed (%s).",
			strerror(errno));
		return (err);
	}

	err = listen(fd, 1);
	if(err < 0)
	{
		syslog(LOG_ERR, "dlsw_load_monitor listen failed (%s).",
			strerror(errno));
		return (err);
	}

	dlsw_count_and_set_fds(fd, &dlsw_all_fds);
	accept_fd = fd;

	syslog(LOG_ERR, "Monitor port activated (%d).", m->port);

	return (fd);
}

int dlsw_process_monitor(int fd)
{
	struct sockaddr_in clt_addr;
	struct sockaddr_in *in;
	struct mon_clt *m;
	int err, addrlen;

	memset(&clt_addr, 0, sizeof(clt_addr));
	in = &clt_addr;
	addrlen = sizeof(clt_addr);
	err = accept(fd, (struct sockaddr *)&clt_addr, &addrlen); 
	if(err < 0)
	{
		syslog(LOG_ERR, "dlsw_process_monitor accept failed (%s).",
			strerror(errno));
		return (err);
	}

	if(!new(m))
		return (-ENOMEM);
	memcpy(&m->ipaddr, in, sizeof(struct sockaddr_in));
	dlsw_count_and_set_fds(err, &dlsw_all_fds);
	m->fd 		= err;
	m->next 	= monitor_list;
	monitor_list 	= m;

	syslog(LOG_ERR, "Monitor connection accepted from (%s:%d).",
		inet_ntoa(in->sin_addr), ntohs(in->sin_port));

	return (0);
}

/* user wants us dead, so lets cleanup and die. */
void dlsw_signal_goaway(int signum)
{
	struct mon_clt *m;

        (void)signum;

	for(m = monitor_list; m != NULL; m = m->next)
        {
                dlsw_count_and_clear_fds(m->fd, &dlsw_all_fds);
                close(m->fd);
        }
	dlsw_delete_monitor_list();
	if(dlsw_config_info)
		free(dlsw_config_info);

	if(accept_fd)
	{
		close(accept_fd);
		dlsw_count_and_clear_fds(accept_fd, &dlsw_all_fds);
	}

	syslog(LOG_ERR, "Structured tear-down complete (%d).", 
		dlsw_stats->open_fds);
	free(dlsw_stats);

        (void)unlink(_PATH_DLSWDPID);
        closelog();

        exit (0);
}

static int dlsw_director(void)
{
	fd_set readable;
	int fd, i;

        syslog(LOG_INFO, "Director activated.\n");

	sig_block();
        for(;;)
        {
		readable = dlsw_all_fds;

		sig_unblock();
		fd = select(dlsw_stats->highest_fd + 1, &readable, 
			NULL, NULL, NULL);
		sig_block();

		dlsw_stats->director_events++;
		if(fd < 0)	/* check for immediate errors. */
		{
			if(fd < 0 && errno != EINTR) 
			{
                                syslog(LOG_ERR, "select failed: %s",
					strerror(errno));
                                sleep(1);
                        }
			dlsw_stats->director_errors++;
                        continue;
		}

		/* find which fd has an event for us. */
		for(i = 3; i <= dlsw_stats->highest_fd; i++)
		{
                        if(FD_ISSET(i, &readable))
			{
				if(accept_fd == i)
				{
					dlsw_stats->monitor_events++;
					dlsw_process_monitor(i);
					continue;
				}

				if(dlsw_find_monitor_by_fd(i))
				{
					dlsw_stats->monitor_events++;
					dlsw_monitor_process_data(i);
					continue;
				}

				/* dlsw is suspended by monitor. */
				if(dlsw_stats->suspend)
				{
					dlsw_stats->suspend_events_tossed++;
					continue;
				}

				/* now we do something useful. */
                        }
                }
	}

        return (0);
}

int dlsw_init_local_ssp_sockets(void)
{
	struct sockaddr_in sin;
	int err;

	local_write_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(local_write_fd < 0)
		return (local_write_fd);
	local_read_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(local_read_fd < 0)
	{
		close(local_write_fd);
		return (local_read_fd);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family	= PF_INET;
	sin.sin_port	= htons(SSP_READ_PORT);
	sin.sin_addr.s_addr = INADDR_ANY;
	err = bind(local_read_fd, (struct sockaddr *)&sin, sizeof(sin));
	if(err < 0)
		goto error;

	memset(&sin, 0, sizeof(sin));
        sin.sin_family  = PF_INET;
        sin.sin_port    = htons(SSP_WRITE_PORT);
        sin.sin_addr.s_addr = INADDR_ANY;
	err = bind(local_write_fd, (struct sockaddr *)&sin, sizeof(sin));
        if(err < 0)
		goto error;

	err = listen(local_read_fd, SSP_READ_PORT_BACKLOG);
	if(err < 0)
		goto error;

	err = listen(local_write_fd, SSP_WRITE_PORT_BACKLOG);
        if(err < 0)
                goto error;

	return (0);

error:
	close(local_write_fd);
        close(local_read_fd);
        return (err);
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
        if(blocked)
        {
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

        if((fp = fopen(_PATH_DLSWDPID, "w")) != NULL)
	{
                fprintf(fp, "%u\n", getpid());
                (void)fclose(fp);
        }
}

/* display the applications version and information. */
void version(void)
{
        printf("%s: %s %s\n%s %s\n", name_s, desc_s, version_s,
                company_s, maintainer_s);
        exit(1);
}

void help(void)
{
        printf("Usage: dlswd [-h] [-V] [-d level] [-f config]\n");
        exit(1);
}

int main(int argc, char **argv)
{
        int err, c;

	if(!new(dlsw_stats))
		return (-ENOMEM);
	FD_ZERO(&dlsw_all_fds);
	while((c = getopt(argc, argv, "hvVf:d:")) != EOF)
        {
                switch(c) {
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

	err = load_config_file(config_file);
        if(err < 0)
        	dlsw_signal_goaway(0);    /* clean&die */

        openlog(name_s, LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "%s %s", desc_s, version_s);

        if(nodaemon == 0)
                daemon(0, 0);

	/* log our pid for scripts. */
	logpid();

        /* setup signal handling */
        sig_init();

	err = load_config(dlsw_config_info);
        if(err < 0)
                dlsw_signal_goaway(0);    /* clean&die */

	err = dlsw_init_local_ssp_sockets();
	if(err < 0)
	{
		syslog(LOG_ERR, "Initialization of local SSP read/write sockets failed (%d)", err);
		dlsw_signal_goaway(0);
	}
	else
		syslog(LOG_ERR, "Initialization of local SSP read/write sockets complete");

        /* we do the real work now, looping and directing. */
        err = dlsw_director();
	return (err);
}
