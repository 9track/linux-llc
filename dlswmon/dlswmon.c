/* dlswmonitor.c: Portal to the data link switching world.
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
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <dlfcn.h>
#include <pwd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/utsname.h>

#include "parse.h"

#include <sysinfo.h>
#include <readproc.h>

#include <dlsw_load.h>
#include <dlswd.h>
#include "dlswmonitor.h"

fd_set all_fds;
int highest_fd = 0;

struct wordmap on_types[] = {
        { "off",        0               },
        { "on",         1               },
        { NULL,         -1              }
};

#define LINUX_VERSION(x,y,z)   (0x10000*(x) + 0x100*(y) + z)

char version_s[] 	= VERSION;
char name_s[] 		= PACKAGE;
char maintainer_s[] 	= "Jay Schulist <jschlst@samba.org>";
char company_s[] 	= "Screaming Daemon, Inc.";
char desc_s[] 		= "Dlswd remote monitor";
char prompt[sizeof(name_s) + 2], line[200];
int server_fd = 0, connected = 0, bell = 0, proxy = 0;

extern struct cmd cmdtab[];
extern int NCMDS;

int dlsw_send_cmd(int fd, int rx_cmd)
{
	struct dlm_cmd cmd;
	int err;

	cmd.cmd = rx_cmd;
        err = send(fd, (void *)&cmd, sizeof(cmd), 0);
        if(err < 0)
                printf("dlsw_send_cmd: failed send(%d, %d).\n", fd, rx_cmd);
        return (err);
}

int dlsw_rx_errno(int fd)
{
	char b[sizeof(struct dlm_result)];
	struct dlm_result *r;
	int len;

	len = recv(fd, b, sizeof(b), 0);
	if(len <= 0)
	{
		printf("dlsw_rx_errno: failed recv (%d).\n", len);
		return (len);
	}
	if(len < sizeof(struct dlm_result))
	{
		printf("nr_rx_errno: length too small (%d).\n", len);
		return (len);
	}
	r = (struct dlm_result *)b;
	return (r->error);
}

void suspend(void)
{
	int err;
	dlsw_send_cmd(server_fd, SUSPEND);
	err = dlsw_rx_errno(server_fd);
	if(err < 0)
	{
	        printf("%s: command failed (%d).\n", "suspend", err);
                return;
        }

        printf("%s: command successful.\n", "suspend");
	return;
}

void resume(void)
{
	int err;
        dlsw_send_cmd(server_fd, RESUME);
        err = dlsw_rx_errno(server_fd);
        if(err < 0)
        {
                printf("%s: command failed (%d).\n", "resume", err);
                return;
        }

        printf("%s: command successful.\n", "resume");
        return;
}

void setdebug(int argc, char *argv[])
{
	struct dlm_cmd *cmd;
        struct dlm_debug *d;
        int size, err, level;

        if(argc < 2)
        {
                printf("Invalid syntax:\n");
                printf("  debug [0 - 100]\n");
                return;
        }

	level = atoi(argv[1]);
        if(level < 0 || level > 100)
        {
                printf("Invalid syntax:\n");
                printf("  debug [0 - 100]\n");
                return;
        }

        size = sizeof(struct dlm_cmd) + sizeof(struct dlm_debug);
        cmd = (struct dlm_cmd *)new_s(size);
	if(!cmd)
		return;
        cmd->cmd = DEBUG;
        cmd->size = sizeof(struct dlm_cmd);
        d = (struct dlm_debug *)cmd->data;
	d->level = level;
        send(server_fd, cmd, size, 0);
        err = dlsw_rx_errno(server_fd);
        if(err < 0)
        {
                printf("%s: command failed (%d).\n", "debug", err);
                free(cmd);
                return;
        }

        printf("%s: command successful.\n", "debug");
        free(cmd);
        return;
}

int dlsw_recv_cmd_data(int fd, char *b, int b_size)
{
	int len;

	len = recv(fd, b, b_size, 0);
        if(len <= 0)
                printf("dlsw_recv_cmd_data: failed recv(%d).\n", len);
        return (len);
}

#define dlsw_iterate_print(entry, pr, arg1)			\
do {								\
	unsigned int __i, __err;				\
	struct dlm_entries *__e = (void *)(entry);		\
								\
	for(__i = 0; __i < __e->size; __i += __e->ssize)	\
	{							\
		__err = pr((void *)(__e->data + __i), arg1);	\
		if(__err < 0)					\
			break;					\
	}							\
	__err;							\
} while(0)

int map_word(struct wordmap *wm, const char *word)
{
        int i;
        for(i = 0; wm[i].word != NULL; i++)
                if(!strcmp(wm[i].word, word))
                        return (wm[i].val);

        return (-1);
}

int dlsw_print_network(struct dlm_iface *iface, void *arg1)
{
	printf("Iface: %s\n", iface->name);
        printf("  RX packets:%ld bytes:%ld errors:%ld dropped:%ld overruns:%ld frame:%ld\n",
		iface->rx_packets, iface->rx_bytes, iface->rx_errs,
                iface->rx_drop, iface->rx_fifo, iface->rx_frame);
        printf("  TX packets:%ld bytes:%ld errors:%ld dropped:%ld overruns:%ld carrier:%ld\n",
                iface->tx_packets, iface->tx_bytes, iface->tx_errs,
                iface->tx_drop, iface->tx_fifo, iface->tx_carrier);
        printf("  collisions:%ld\n", iface->tx_colls);

	return (0);
}

void network(void)
{
        char buf[sizeof(struct dlm_entries) + 1024];

	if(dlsw_send_cmd(server_fd, NETWORK) < 0)
		return;
	if(dlsw_recv_cmd_data(server_fd, buf, sizeof(buf)) < 0)
		return;

	printf("Network information:\n");
	dlsw_iterate_print(buf, dlsw_print_network, NULL);

	return;
}

char *display_kernel_version(struct utsname *uts)
{
	static char buff[150];
	int x = 0, y = 0, z = 0;    /* cleared in case sscanf() < 3 */

    	if(sscanf(uts->release, "%d.%d.%d", &x, &y, &z) < 3)
        	sprintf(buff,
	                "Non-standard uts for running kernel:\n"
	                "release %s=%d.%d.%d gives version code %d\n",
	                uts->release, x, y, z, LINUX_VERSION(x,y,z));
	else
		sprintf(buff, "%d.%d.%d", x, y, z);

	return (buff);
}

char *display_uptime(double uptime_secs, double idle_secs)
{
	static char buf[150];
	int upminutes, uphours, updays;
	int pos = 0;

	updays = (int) uptime_secs / (60*60*24);
  	if(updays)
    		pos += sprintf(buf + pos, "%d day%s, ", 
		updays, (updays != 1) ? "s" : "");
  	upminutes = (int) uptime_secs / 60;
  	uphours = upminutes / 60;
  	uphours = uphours % 24;
  	upminutes = upminutes % 60;
  	if(uphours)
    		pos += sprintf(buf + pos, "%2d:%02d", uphours, upminutes);
  	else
    		pos += sprintf(buf + pos, "%d min", upminutes);

	return (buf);
}

char *display_state(char *c)
{
	static char buf[50];
	if(!strncmp("S", c, 1))
		sprintf(buf, "S (sleeping)");
	if(!strncmp("R", c, 1))
		sprintf(buf, "R (running)");
	if(!strncmp("Z", c, 1))
		sprintf(buf, "Z (zombie)");
	if(!strncmp("T", c, 1))
		sprintf(buf, "T (traced)");
	if(!strncmp("D", c, 1))
		sprintf(buf, "D (uninteruptible sleep)");
	return (buf);
}

extern int uptime(double *uptime_secs, double *idle_secs);
extern unsigned long Hertz;

void status(void)
{
	struct dlm_status *sc;
	struct dlsw_statistics *d;
	proc_t *np;
	char buf[sizeof(struct dlm_status)];
	unsigned long total_time, seconds, seconds_since_boot, pcpu = 0;
	seconds_since_boot = uptime(0,0);

	if(dlsw_send_cmd(server_fd, STATUS) < 0)
		return;
	if(dlsw_recv_cmd_data(server_fd, buf, sizeof(buf)) < 0)
		return;

        sc = (struct dlm_status *)buf;
	np = &sc->dl_proc;

  	total_time = np->utime + np->stime;
  	seconds = (seconds_since_boot - ((unsigned long)np->start_time)/Hertz);
  	if(seconds) 
		pcpu = ((long long)total_time * 1000 / Hertz) / seconds;
  	np->pcpu = (pcpu > 999)? 999 : pcpu;


	printf("DLSwd status:\n");
	printf("  Name: %s, State: %s\n", sc->dl_proc.cmd, 
		display_state(&np->state));
	printf("  Pid %d, Parent Pid %d, UserID %d\n", np->pid, np->ppid, 
		np->ruid);
	printf("  Priority %ld, Nice %ld, %%CPU %2u.%u\n",
		np->priority, np->nice, (unsigned)(np->pcpu/10), 
		(unsigned)(np->pcpu % 10));
	printf("  Memory:\n");
	printf("   Pages: Total %ld, Shared %ld, Dirty %ld\n", 
		np->resident, np->share, np->dt);
	printf("   TextRs %ld, ShLibRs %ld, DataRs %ld\n", 
		np->trs, np->lrs, np->drs);

	d = &sc->statistics;
	printf("  FD open:%lu watermark:%lu\n", d->open_fds, d->wmark_fd);
        printf("  Director EVT total:%lu errors:%lu suspend:%lu\n",
                d->director_events, d->director_errors,
                d->suspend_events_tossed);
        printf("  Monitor  EVT total:%lu errors:%lu\n",
                d->monitor_events, d->monitor_errors);
        printf("  MON tbytes:%lu terrors:%lu tdropped:%lu"
                " rbytes:%lu rerrors:%lu rdropped:%lu\n",
                d->monitor_tx_bytes, d->monitor_tx_errors, d->monitor_tx_drops,
                d->monitor_rx_bytes, d->monitor_rx_errors, d->monitor_rx_drops);

	return;
}

void syst(void)
{
	struct dlm_system *sc;
	char buf[sizeof(struct dlm_system)];

	if(dlsw_send_cmd(server_fd, SYSTEM) < 0)
		return;
	if(dlsw_recv_cmd_data(server_fd, buf, sizeof(buf)) < 0)
		return;

	sc = (struct dlm_system *)buf;
	printf("System information:\n");
	printf("  Os: %s, Cpu/HrdWare: %s\n", 
		sc->name.sysname, sc->name.machine);
	printf("  Node: %s\n", sc->name.nodename);
	printf("  Uptime %s, %d Users, Kernel version %s\n", 
		display_uptime(sc->uptime_secs, sc->idle_secs), 
		sc->num_users, display_kernel_version(&sc->name));
	printf("  Load average: %.2f, %.2f, %.2f\n",
		sc->load_avg_1, sc->load_avg_5, sc->load_avg_15);
	printf("  MemTotal:   %LdK\n", sc->mem_total >> 10);
	printf("  MemUsed:    %LdK\n", sc->mem_used >> 10);
	printf("  MemFree:    %LdK\n", sc->mem_free >> 10);
	printf("  MemShared:  %LdK\n", sc->mem_shared >> 10);
	printf("  MemBuffers: %LdK\n", sc->mem_buffers >> 10);
	printf("  MemCached:  %LdK\n", sc->mem_cached >> 10);

	return;
}

void disconnect(void)
{
	if(!connected)
		return;
	if(server_fd)
	{
		FD_CLR(server_fd, &all_fds);
		close(server_fd);
	}
	connected = 0;
	return;
}

void quit(void)
{
	disconnect();
	exit(0);
}

struct sockaddr_in server;

char *do_connect(char *host, int port)
{
	static char hostnamebuf[256];
	struct hostent *hp = 0;
	int fd, err;

	/* get hostname. */
	memset(&server, 0, sizeof(server));
        if(inet_aton(host, &server.sin_addr)) 
	{
                server.sin_family = AF_INET;
                strncpy(hostnamebuf, host, sizeof(hostnamebuf));
                hostnamebuf[sizeof(hostnamebuf)-1] = 0;
        }
        else 
	{
                hp = gethostbyname(host);
                if(hp == NULL)
		{
                        fprintf(stderr, "%s: %s: ", name_s, host);
                        herror((char *)NULL);
                        return((char *) 0);
                }
                server.sin_family = hp->h_addrtype;
                if(hp->h_length > (int)sizeof(server.sin_addr))
                        hp->h_length = sizeof(server.sin_addr);
                memcpy(&server.sin_addr, hp->h_addr_list[0], hp->h_length);
                strncpy(hostnamebuf, hp->h_name, sizeof(hostnamebuf));
                hostnamebuf[sizeof(hostnamebuf)-1] = 0;
        }

	fd = socket(server.sin_family, SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0)
	{
		printf("socket failed\n");
		return (NULL);
	}
	server.sin_port = port;
	err = connect(fd, (struct sockaddr *)&server, sizeof(server));
	if(err < 0)
	{
		printf("Unable to connect to %s:%d\n", hostnamebuf,ntohs(port));
		close(fd);
		return (NULL);
	}

	printf("Connected to %s:%d\n", hostnamebuf, ntohs(port));

	server_fd = fd;
	FD_SET(server_fd, &all_fds);
	if(server_fd > highest_fd)
                highest_fd = server_fd;
	return (hostnamebuf);
}

/* connect to a monitor. */
void open_monitor(int argc, char *argv[])
{
	char *host;
        unsigned short port;

	if(connected)
	{
                printf("Already connected to %s, use close first.\n",
                        "Blahhh"); // hostname);
                return;
        }
	if(argc < 2)
                (void) another(&argc, &argv, "to");
        if(argc < 2 || argc > 3)
	{
                printf("usage: %s host-name [port]\n", argv[0]);
                return;
        }
	port = htons(4110); // monitor_port;
        if(argc > 2)
	{
                port = atoi(argv[2]);
                if(port < 1) {
                        printf("%s: bad port number-- %s\n", argv[1], argv[2]);
                        printf ("usage: %s host-name [port]\n", argv[0]);
                        return;
                }
                port = htons(port);
        }
	host = do_connect(argv[1], port);
	if(host)
	{
		connected = 1;

		/* lets transfer some system information here. */
	}

	return;
}

#define HELPINDENT ((int) sizeof ("directory"))
void help(int argc, char *argv[])
{
        struct cmd *c;

        if (argc == 1) {
                int i, j, w;
                unsigned k;
                int columns, width = 0, lines;

                printf("Commands may be abbreviated.  Commands are:\n\n");
                for (c = cmdtab; c < &cmdtab[NCMDS]; c++) {
                        int len = strlen(c->c_name);

                        if (len > width)
                                width = len;
                }
                width = (width + 8) &~ 7;
                columns = 80 / width;
                if (columns == 0)
                        columns = 1;
                lines = (NCMDS + columns - 1) / columns;
                for (i = 0; i < lines; i++) {
                        for (j = 0; j < columns; j++) {
                                c = cmdtab + j * lines + i;
                                if (c->c_name && (!proxy || c->c_proxy)) {
                                        printf("%s", c->c_name);
                                }
                                else if (c->c_name) {
                                        for (k=0; k < strlen(c->c_name); k++) {
                                                (void) putchar(' ');
                                        }
                                }
                                if (c + lines >= &cmdtab[NCMDS]) {
                                        printf("\n");
                                        break;
                                }
                                w = strlen(c->c_name);
                                while (w < width) {
                                        w = (w + 8) &~ 7;
                                        (void) putchar('\t');
                                }
                        }
                }
                return;
        }
        while (--argc > 0) {
                register char *arg;
                arg = *++argv;
                c = getcmd(arg);
                if (c == (struct cmd *)-1)
                        printf("?Ambiguous help command %s\n", arg);
                else if (c == NULL)
                        printf("?Invalid help command %s\n", arg);
                else
                        printf("%-*s\t%s\n", HELPINDENT,
                                c->c_name, c->c_help);
        }
}

void pr_tease(void)
{
	printf("%s", prompt);
        fflush(stdout);
}

void do_tease(void)
{
	int margc;
        char *marg;
        char **margv;
        struct cmd *c;
        int l;

	fgets(line, sizeof(line), stdin);

	l = strlen(line);
        if(l == 0)
		return;
        if(line[--l] == '\n')
        {
        	if(l == 0)
			return;
                line[l] = '\0';
        }
        else
        {
	        if(l == sizeof(line) - 2)
                {
  	        	printf("sorry, input line too long\n");
                      	while((l = getchar()) != '\n' && l != EOF)
                      		return;	/* void */;
                } /* else it was a line without a newline */
        }
        margv = nmakeargv(&margc, &marg);
        if(margc == 0)
		return;
        c = getcmd(margv[0]);
        if (c == (struct cmd *)-1) {
        	printf("?Ambiguous command\n");
		return;
	}
        if (c == NULL) {
        	printf("?Invalid command\n");
		return;
	}
        if (c->c_conn && !connected) {
        	printf("Not connected.\n");
		return;
	}
        if (c->c_handler_v) c->c_handler_v(margc, margv);
        else if (c->c_handler_0) c->c_handler_0();
        else c->c_handler_1(marg);

        if (bell && c->c_bell) putchar('\007');
        if (c->c_handler_v != help)
		return;
}

int do_recv(int fd)
{
	char buf[1024];
	int len;

	len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if(len <= 0)
		return (len);

	printf("\n");
	printf("%s", "do_recv got data");

	return (0);
}

/* display the applications version and information. */
void version(void)
{
        printf("%s: %s %s\n%s %s\n", name_s, desc_s, version_s,
                company_s, maintainer_s);
        exit(1);
}

void help_cmdline(void)
{
        printf("Usage: dlswmon [-h] [-V] [-s server_addr:port]\n");
	printf("  [-d (status|system)]\n");
        exit(1);
}

int main(int argc, char **argv)
{
	fd_set readable;
	int fd, i, c, cmdline = 0;

	while((c = getopt(argc, argv, "hvVs:d:")) != EOF)
        {
		int margc;
        	char *marg;
        	char **margv;

                switch(c) {
			case 's':	/* get server addr:port */
			{
				char *a = strtok(optarg, ":");
				char *p = strtok(NULL, ":");
				sprintf(line, "open %s %s", a, p);
				margv = nmakeargv(&margc, &marg);
        			if(margc == 0)
                			return (-1);
				open_monitor(margc, margv);
				cmdline = 1;
				break;
			}

			case 'd':	/* display some information */
			{
				if(!strcmp("status", optarg))
					status();
				if(!strcmp("system", optarg))
					syst();
				break;
			}

			case 'V':       /* Display author and version. */
                        case 'v':       /* Display author and version. */
                                version();
                                break;

                        case 'h':       /* Display useless help information. */
                                help_cmdline();
                                break;
                }
        }

	if(cmdline)
		quit();

	sprintf(prompt, "%s> ", name_s);
	FD_ZERO(&all_fds);
        FD_SET(0, &all_fds);	/* stdin. */
	if(0 > highest_fd)
                highest_fd = 0;

	pr_tease();
	for(;;)
	{
		readable = all_fds;
		fd = select(highest_fd + 1, &readable, NULL, NULL, NULL);
		if(fd < 0)      /* check for immediate errors. */
                {
                        if(fd < 0 && errno != EINTR)
                        {
                                printf("select failed: %s", strerror(errno));
                                sleep(1);
                        }
                        continue;
                }

		for(i = 0; i <= highest_fd; i++)
                {
                        if(FD_ISSET(i, &readable))
                        {
				if(i >= 3)
                                        do_recv(i);
				if(i == 0)
				{
					do_tease();
					pr_tease();
				}
			}
		}
	}

	return (0);
}
