/* dlsw_monitor.c: file that contains all server side monitor data proc code.
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
#include <syslog.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utmp.h>
#include <sys/utsname.h>
#include <stdarg.h>

#include <sysinfo.h>
#include <readproc.h>

#include <dlsw_load.h>
#include <dlswd.h>
#include <dlsw_monitor.h>
#include <dlswmonitor.h>

extern fd_set dlsw_all_fds;
extern global *dlsw_config_info;
extern struct dlsw_statistics *dlsw_stats;
extern struct mon_clt *monitor_list;

int buffsize = 1024;

int dlsw_monitor_send(int fd, const void *msg, size_t len, int flags)
{
	int err;

	err = send(fd, msg, len, flags);
	if(err < 0)
        	dlsw_stats->monitor_tx_errors++;
        else
                dlsw_stats->monitor_tx_bytes += len;        

	return (err);
}

char *proc_gen_fmt(char *name, int more, FILE * fh,...)
{
    char buf[512], format[512] = "";
    char *title, *head, *hdr;
    va_list ap;

    if (!fgets(buf, (sizeof buf) - 1, fh))
        return NULL;
    strcat(buf, " ");

    va_start(ap, fh);
    title = va_arg(ap, char *);
    for (hdr = buf; hdr;) {
        while (isspace(*hdr) || *hdr == '|')
            hdr++;
        head = hdr;
        hdr = strpbrk(hdr, "| \t\n");
        if (hdr)
            *hdr++ = 0;

        if (!strcmp(title, head)) {
            strcat(format, va_arg(ap, char *));
            title = va_arg(ap, char *);
            if (!title || !head)
                break;
        } else {
            strcat(format, "%*s");      /* XXX */
        }
        strcat(format, " ");
    }
    va_end(ap);

    if (!more && title) {
        fprintf(stderr, "warning: %s does not contain required field %s\n",
                name, title);
        return NULL;
    }
    return strdup(format);
}

int dlsw_process_network_cmd(int fd)
{
	struct dlm_entries *e;
	char *fmt, b[buffsize];
	FILE *fh;
	int err;

	fh = fopen(_PATH_PROC_NET_DEV, "r");
    	if(!fh)
	{
		syslog(LOG_ERR, "Proc not enabled!\n");
		return (-ENOENT);
	}

	fgets(b, sizeof(b), fh); /* eat line */
	fmt = proc_gen_fmt(_PATH_PROC_NET_DEV, 0, fh,
                       "face", "%16s",      /* parsed separately */
                       "bytes", "%lu",
                       "packets", "%lu",
                       "errs", "%lu",
                       "drop", "%lu",
                       "fifo", "%lu",
                       "frame", "%lu",
                       "compressed", "%lu",
                       "multicast", "%lu",
                       "bytes", "%lu",
                       "packets", "%lu",
                       "errs", "%lu",
                       "drop", "%lu",
                       "fifo", "%lu",
                       "colls", "%lu",
                       "carrier", "%lu",
                       "compressed", "%lu",
                       NULL);
    	if(!fmt)
        	return (-EINVAL);

	new(e);
	if(!e)
		return (-ENOMEM);
        e->ssize = 0;

	while(fgets(b, (buffsize - 1), fh)) 
	{
		struct dlm_iface *data;

		e->num++;
                e = (void *)realloc(e, sizeof(e) + (e->num * e->ssize));
                data = (void *)(e->data + ((e->num - 1) * e->ssize));
                e->size += e->ssize;

		sscanf(b, fmt, data->name, &data->rx_bytes, 
			&data->rx_packets, &data->rx_errs, &data->rx_drop,
			&data->rx_fifo, &data->rx_frame, 
			&data->rx_compressed, &data->rx_multicast,
			&data->tx_bytes, &data->tx_packets, &data->tx_errs,
			&data->tx_drop, &data->tx_fifo, &data->tx_colls,
			&data->tx_carrier, &data->tx_compressed);
	}

	err = dlsw_monitor_send(fd, e, (e->size + sizeof(struct dlm_entries)), 0);
        free(e);
	free(fmt);
	fclose(fh);

	return (err);
}

int dlsw_process_status_cmd(int fd)
{
	struct dlm_status sc;
	look_up_our_self(&sc.dl_proc);
	memcpy(&sc.statistics, dlsw_stats, sizeof(struct dlsw_statistics));

        return (dlsw_monitor_send(fd, &sc, sizeof(struct dlm_status), 0));
}

int dlsw_process_system_cmd(int fd)
{
	struct dlm_system sc;
	unsigned long long **mem;
	struct utmp *utmpstruct;

	memset(&sc, 0, sizeof(sc));

	setutent();
  	while ((utmpstruct = getutent())) 
	{
    		if((utmpstruct->ut_type == USER_PROCESS)
       			&& (utmpstruct->ut_name[0] != '\0'))
      			sc.num_users++;
  	}
  	endutent();

	uname(&sc.name);

	if(!(mem = meminfo()) || mem[meminfo_main][meminfo_total] == 0)
		return (-EINVAL);
	sc.mem_total 	= mem[meminfo_main][meminfo_total];
	sc.mem_used	= mem[meminfo_main][meminfo_used];
	sc.mem_free	= mem[meminfo_main][meminfo_free];
	sc.mem_shared	= mem[meminfo_main][meminfo_shared];
	sc.mem_buffers	= mem[meminfo_main][meminfo_buffers];
	sc.mem_cached	= mem[meminfo_main][meminfo_cached];

	uptime(&sc.uptime_secs, &sc.idle_secs);
	loadavg(&sc.load_avg_1, &sc.load_avg_5, &sc.load_avg_15);

        return (dlsw_monitor_send(fd, (void *)&sc, sizeof(sc), 0));
}

int dlsw_tx_errno(int fd, int err_code)
{
	struct dlm_result r;
	int err;

	dlsw_stats->monitor_tx_bytes += sizeof(struct dlm_result);

	r.error = err_code;
	err = dlsw_monitor_send(fd, &r, sizeof(struct dlm_result), 0);
	if(err < 0)
		dlsw_stats->monitor_tx_errors++;
	else
                dlsw_stats->monitor_tx_bytes += sizeof(struct dlm_result);

	return (err);
}

int dlsw_process_suspend_cmd(int fd)
{
	dlsw_stats->suspend = 1;
	return (dlsw_tx_errno(fd, 0));
}

int dlsw_process_statistic_cmd(int fd)
{
	return (dlsw_monitor_send(fd, dlsw_stats, sizeof(struct dlsw_statistics), 0));
}

int dlsw_process_resume_cmd(int fd)
{
	dlsw_stats->suspend = 0;
	return (dlsw_tx_errno(fd, 0));
}

int dlsw_process_debug_cmd(int fd, struct dlm_debug *d)
{
	if(d->level < 0 || d->level > 100)
		return (dlsw_tx_errno(fd, -EBADMSG));

	dlsw_stats->debug = d->level;
	return (dlsw_tx_errno(fd, 0));
}

int dlsw_monitor_process_data(int fd)
{
        char buf[buffsize];
        int len;
        struct dlm_cmd *cmd;

        len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if(len <= 0)
	{
		struct mon_clt *m;

		dlsw_count_and_clear_fds(fd, &dlsw_all_fds);
		m = dlsw_find_monitor_by_fd(fd);
		if(m)
		{
			syslog(LOG_ERR, "Monitor client disconnected (%s:%d).",
				inet_ntoa(m->ipaddr.sin_addr), 
				ntohs(m->ipaddr.sin_port));
			dlsw_monitor_delete(fd);
		}
                return (len);
	}
        if(len < sizeof(struct dlm_cmd))
	{
		dlsw_stats->monitor_rx_errors++;
                return (-EBADMSG);
	}

	dlsw_stats->monitor_rx_bytes += len;
        cmd = (struct dlm_cmd *)buf;
        switch(cmd->cmd) {
                case (SYSTEM):
                        dlsw_process_system_cmd(fd);
                        break;
		case (STATUS):
			dlsw_process_status_cmd(fd);
			break;
		case (NETWORK):
			dlsw_process_network_cmd(fd);
			break;
		case (SUSPEND):
			dlsw_process_suspend_cmd(fd);
			break;
		case (RESUME):
			dlsw_process_resume_cmd(fd);
			break;
		case (DEBUG):
			dlsw_process_debug_cmd(fd, (void *)cmd->data);
			break;
                default:
                        break;
        };

        return (0);
}


