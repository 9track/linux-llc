/* dlsw_ssp.c: switch-to-switch related functions.
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

/* our stuff. */
#include <dlsw_ssp.h>
#include <dlsw_vector.h>
#include <dlsw_list.h>
#include <dlsw_timer.h>
#include <dlswd_load.h>
#include <dlswd.h>

int dlsw_ssp_dump_info(ssp_info_t *ssp)
{
	 printf(__FUNCTION__ ": ssp information header dump\n");
         printf("version       = %02X\n", ssp->version);
         printf("  hdrlen      = %d\n", ssp->hdrlen);
         printf("  msglen      = %d\n", ntohs(ssp->msglen));
         printf("  rdlc        = %04X\n", ssp->rdlcr);
         printf("  rdlc_pid    = %04X\n", ssp->rdlc_pid);
         printf("  rsv0        = %02X\n", ssp->rsv0);
         printf("  msgtype     = %02X\n", ssp->msgtype);
         printf("  flowctrl    = %02X\n", ssp->flowctrl);
	 return 0;
}

int dlsw_ssp_dump_ctrl(ssp_ctrl_t *ssp)
{       
        printf(__FUNCTION__ ": ssp control header dump\n");
        printf("version       = %02X\n", ssp->version);
        printf("  hdrlen      = %d\n", ssp->hdrlen);
        printf("  msglen      = %d\n", ntohs(ssp->msglen));
        printf("  rdlc        = %04X\n", ssp->rdlcr);
        printf("  rdlc_pid    = %04X\n", ssp->rdlc_pid);
        printf("  rsv0        = %02X\n", ssp->rsv0);
        printf("  msgtype     = %02X\n", ssp->msgtype);
        printf("  flowctrl    = %02X\n", ssp->flowctrl);
        printf("  proto       = %02X\n", ssp->proto);
        printf("  hdrnum      = %02X\n", ssp->hdrnum);
        printf("  rsv1        = %02X\n", ssp->rsv1);
        printf("  lfs         = %02X\n", ssp->lfs);
        printf("  flags       = %02X\n", ssp->flags);
        printf("  priority    = %02X\n", ssp->priority);
        printf("  oldmsgtype  = %02X\n", ssp->oldmsgtype);
        printf("  tmac_addr   = %s\n", pr_ether(ssp->tmac_addr));
        printf("  omac_addr   = %s\n", pr_ether(ssp->omac_addr));
        printf("  osap        = 0x%02X\n", ssp->osap);
        printf("  tsap        = 0x%02X\n", ssp->tsap);
        printf("  fdir        = %02X\n", ssp->fdir);
    	printf("  rsv2        = %02X\n", ssp->rsv2);
        printf("  rsv3        = %02X\n", ssp->rsv3);
        printf("  dlchdrlen   = %d\n", ssp->dlchdrlen);
        printf("  odlc_pid    = %04X\n", ssp->odlc_pid);
        printf("  odlcr       = %04X\n", ssp->odlcr);
        printf("  tdlc_pid    = %04X\n", ssp->tdlc_pid);
        printf("  tdlcr       = %04X\n", ssp->tdlcr);
        printf("  ttp         = %04X\n", ssp->ttp);
        printf("  rsv4        = %04X\n", ssp->rsv4);
        return 0;
}
