/* llcping.c: Linux LLC Ping Client utility.
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
#include <time.h>
#include <sys/time.h>
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

/* llc libraries headers. */
#include <llcdb.h>

/* our stuff. */
#include "llcping.h"

#ifndef AF_LLC
#define AF_LLC          26
#define PF_LLC          AF_LLC
#endif

#ifndef SOL_LLC
#define SOL_LLC         268
#endif

char version_s[]                        = VERSION;
char name_s[]                           = "llcping";
char desc_s[]                           = "IEEE 802.2 llc echo client";
char maintainer_s[]                     = "Jay Schulist <jschlst@samba.org>";
char web_s[]				= "http://www.linux-sna.org";

static struct llc_options *tmp_llc = NULL;

/* bit swap support. */
#define nibble(v, w)    ((v >> (w * 4)) & 0x0F)
static unsigned char rbits[16] = {
        0x00, 0x08, 0x04, 0x0C, 0x02, 0x0A, 0x06, 0x0E,
        0x01, 0x09, 0x05, 0x0D, 0x03, 0x0B, 0x07, 0x0F
};

unsigned char flip_nibble(unsigned char v)
{
        return (rbits[v & 0x0F]);
}

unsigned char flip_byte(unsigned char v)
{
        return ((flip_nibble(nibble(v, 0)) << 4) | flip_nibble(nibble(v, 1)));
}

char *pr_ether(char *ptr, int numeric)
{
	struct llchostent *lh;
	static char buff[64];

	if(numeric) {
		snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X",
	                (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
	                (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
	        return(buff);
	}

	lh = getllchostbyaddr(ptr, IFHWADDRLEN, ARPHRD_ETHER);
	if(lh) {
		snprintf(buff, sizeof(buff), "%s", lh->lh_name);
		return (buff);
	}

        return("");
}

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

int in_ether(char *bufp, unsigned char *ptr, int flip)
{       
    	char c, *orig; 
    	unsigned val;
        int i = 0;

    	orig = bufp;
    	while((*bufp != '\0') && (i < ETH_ALEN)) {
        	val = 0;
        	c = *bufp++;
        	if(isdigit(c))
            		val = c - '0';
        	else if(c >= 'a' && c <= 'f')
            		val = c - 'a' + 10;
        	else if(c >= 'A' && c <= 'F')
            		val = c - 'A' + 10;
        	else {
            		errno = EINVAL;
            		return (-1);
        	}

        	val <<= 4;
        	c = *bufp;
        	if(isdigit(c))
            		val |= c - '0';
        	else if(c >= 'a' && c <= 'f')
            		val |= c - 'a' + 10;
        	else if(c >= 'A' && c <= 'F')
            		val |= c - 'A' + 10;
        	else if(c == ':' || c == 0)
            		val >>= 4;
        	else {
            		errno = EINVAL;
            		return (-1);
        	}
        	if(c != 0)
            		bufp++;
        	if(flip)
                	*ptr++ = flip_byte((unsigned char)(val & 0377));
        	else
                	*ptr++ = (unsigned char)(val & 0377);
        	i++;

        	/* We might get a semicolon here - not required. */
        	if(*bufp == ':') 
            		bufp++;
    	}

    	return (0);
}

/* load socket options specified by the user. */
int load_options(struct llc_options *llc, char *options)
{
        char *start, sbuf[10240];
	int i;

        if(strlen(options) <= 0)
                return (0);

	i = 0;
        strcpy(sbuf, options);
        start = (void *)strtok(sbuf, ":");
        do {
		switch(i) {
			case 0:		/* retry. */
				llc->retry = atoi(start);
				break;

			case 1:		/* size. */
				llc->size = atoi(start);
				break;

			case 2:		/* ack. */
				llc->ack = atoi(start);
				break;

			case 3:		/* p. */
				llc->p = atoi(start);
				break;

			case 4:		/* reject. */
				llc->reject = atoi(start);
				break;

			case 5:		/* busy. */
				llc->busy = atoi(start);
				break;

			case 6:		/* txwin. */
				llc->txwin = atoi(start);
				break;

			case 7:		/* rxwin. */
				llc->rxwin = atoi(start);
				break;
		}
		i++;
        } while((start = (void *)strtok(NULL, ":")) != NULL);

	return (0);
}

/* set an llc_options structure to defaults. */
int set_llc_defaults(struct llc_options *llc)
{
	if(!llc)
		return (-EINVAL);
	llc->type	= LLC_TYPE_NULL;
	llc->flip	= 0;
	llc->quiet	= 0;
	llc->flood	= 0;
	llc->hexdump	= 0;
	llc->numeric	= 0;
	llc->len	= LLC_DEFAULT_LEN;
	llc->wait	= LLC_DEFAULT_INTERVAL;
	llc->count	= 0;
	llc->ssap	= LLC_DEFAULT_SSAP;
	llc->dsap	= LLC_DEFAULT_DSAP;
	llc->is_root	= (getuid() == 0);
	llc->tmin	= LONG_MAX;
	llc->tmax	= 0;
        time(&llc->last_time);
        llc->last_time--;
	setuid(getuid());
	return (0);
}

/* set socket information on an llc sap. */
int set_llc_sockopt(struct llc_options *llc)
{
	int opt, val, vlen, err;

	if(llc->retry) {
		opt 	= LLC_OPT_RETRY;
		val 	= llc->retry;
		vlen 	= sizeof(val);
		err = setsockopt(llc->sk, SOL_LLC, opt, &val, vlen);
		if(err < 0)
			printf("%s: setsockopt llc->retry failed `%s'.\n",
				name_s, strerror(errno));
	}

	if(llc->size) {
                opt     = LLC_OPT_SIZE;
                val     = llc->size;
                vlen    = sizeof(val);
                err = setsockopt(llc->sk, SOL_LLC, opt, &val, vlen);
                if(err < 0)
                        printf("%s: setsockopt llc->size failed `%s'.\n",
                                name_s, strerror(errno));
        }

	if(llc->ack) {
                opt     = LLC_OPT_ACK_TMR_EXP;
                val     = llc->ack;
                vlen    = sizeof(val);
                err = setsockopt(llc->sk, SOL_LLC, opt, &val, vlen);
                if(err < 0)
                        printf("%s: setsockopt llc->ack failed `%s'.\n",
                                name_s, strerror(errno));
        }

	if(llc->p) {
                opt     = LLC_OPT_P_TMR_EXP;
                val     = llc->p;
                vlen    = sizeof(val);
                err = setsockopt(llc->sk, SOL_LLC, opt, &val, vlen);
                if(err < 0)
                        printf("%s: setsockopt llc->p failed `%s'.\n",
                                name_s, strerror(errno));
        }

	if(llc->reject) {
                opt     = LLC_OPT_REJ_TMR_EXP;
                val     = llc->reject;
                vlen    = sizeof(val);
                err = setsockopt(llc->sk, SOL_LLC, opt, &val, vlen);
                if(err < 0)
                        printf("%s: setsockopt llc->reject failed `%s'.\n",
                                name_s, strerror(errno));
        }

	if(llc->busy) {
                opt     = LLC_OPT_BUSY_TMR_EXP;
                val     = llc->busy;
                vlen    = sizeof(val);
                err = setsockopt(llc->sk, SOL_LLC, opt, &val, vlen);
                if(err < 0)
                        printf("%s: setsockopt llc->busy failed `%s'.\n",
                                name_s, strerror(errno));
        }

	if(llc->txwin) {
                opt     = LLC_OPT_TX_WIN;
                val     = llc->txwin;
                vlen    = sizeof(val);  
                err = setsockopt(llc->sk, SOL_LLC, opt, &val, vlen); 
                if(err < 0)     
                        printf("%s: setsockopt llc->txwin failed `%s'.\n",
                                name_s, strerror(errno));
        }

	if(llc->rxwin) {
                opt     = LLC_OPT_RX_WIN;
                val     = llc->rxwin;
                vlen    = sizeof(val);  
                err = setsockopt(llc->sk, SOL_LLC, opt, &val, vlen); 
                if(err < 0)     
                        printf("%s: setsockopt llc->rxwin failed `%s'.\n",
                                name_s, strerror(errno));
        }     

	return (0);
}

/* display socket information on an llc sap. */
char *display_llc_sockopt(struct llc_options *llc)
{
	static char buf[256];
	int i, blen = 0;

	for(i = LLC_OPT_UNKNOWN + 1; i < LLC_OPT_MAX; i++) {
		int val, vlen, err;

		vlen = sizeof(val);
		err = getsockopt(llc->sk, SOL_LLC, i, &val, (size_t *)&vlen);
		switch(i) {
			case LLC_OPT_RETRY:
				if(err < 0)
					val = err;
				blen += sprintf(buf + blen, "retry:%d ", val);
				break;

	                case LLC_OPT_SIZE:
				if(err < 0) 
                                        val = err;
                                blen += sprintf(buf + blen, "size:%d ", val);
                                break;

	                case LLC_OPT_ACK_TMR_EXP:
				if(err < 0) 
                                        val = err;
                                blen += sprintf(buf + blen, "ack:%d ", val);
                                break;

	                case LLC_OPT_P_TMR_EXP:
				if(err < 0) 
                                        val = err;
                                blen += sprintf(buf + blen, "p:%d ", val);
                                break;

        	        case LLC_OPT_REJ_TMR_EXP:
				if(err < 0) 
                                        val = err;
                                blen += sprintf(buf + blen, "reject:%d ", val);
                                break;

        	        case LLC_OPT_BUSY_TMR_EXP:
				if(err < 0) 
                                        val = err;
                                blen += sprintf(buf + blen, "busy:%d ", val);
                                break;

			case LLC_OPT_TX_WIN:
				if(err < 0)
                                        val = err;
                                blen += sprintf(buf + blen, "txwin:%d ", val);
                                break;

			case LLC_OPT_RX_WIN:
				if(err < 0)
                                        val = err;
                                blen += sprintf(buf + blen, "rxwin:%d ", val);
                                break;

                	default:
				if(err < 0) 
                                        val = err;
                                blen += sprintf(buf + blen, "unknown:%d:%d ", i, val);
                                break;
		}
	}

	return (buf);
}

/* setup llc socket based on llc type. */
int setup_llc_socket(struct llc_options *llc)
{
	struct sockaddr_llc *to;
	int sk_type, err;

	if(llc->type == 2)
		sk_type = SOCK_STREAM;
	else
		sk_type = SOCK_DGRAM;
	llc->sk = socket(PF_LLC, sk_type, 0);
	if(llc->sk < 0) {
		if(errno == EPERM)
			printf("%s: must run as root.\n", name_s);
		else
			printf("%s: socket `%s'.\n", name_s, strerror(errno));
		if(errno == EAFNOSUPPORT)
                        printf("%s: did you load the llc module?\n", name_s);
		return (llc->sk);
	}

	to = &llc->dst;
	to->sllc_family	= PF_LLC;
	to->sllc_arphrd = ARPHRD_ETHER;
	to->sllc_test	= 0;
	to->sllc_xid	= 0;
	to->sllc_ua	= 0;
	to->sllc_sap	= llc->ssap;
	memcpy(&to->sllc_mac, &llc->smac, IFHWADDRLEN);
	if(llc->type == LLC_TYPE_NULL)
		to->sllc_test = 1;

	err = bind(llc->sk, (struct sockaddr *)&llc->dst, 
		sizeof(struct sockaddr_llc));
	if(err < 0) {
		printf("%s: bind %s.\n", name_s, strerror(errno));
		close(llc->sk);
		return (err);
	}

	if(sk_type != SOCK_STREAM)
		return (0);

	to->sllc_sap	= llc->dsap;
	memcpy(&to->sllc_mac, &llc->dmac, IFHWADDRLEN);

	err = connect(llc->sk, (struct sockaddr *)&llc->dst, 
		sizeof(struct sockaddr_llc));
	if(err < 0) {
		printf("%s: connect %s.\n", name_s, strerror(errno));
		close(llc->sk);
		return (err);
	}

	return (0);
}

/* display the applications version and information. */
void version(void)
{       
        printf("%s: %s %s\n%s\n", name_s, desc_s, version_s,
                maintainer_s);
	printf("%s\n", web_s);
        exit(1);
}       

/* display useless help. */ 
void help(void)
{
        printf("Usage: %s [-h] [-v] [-t 1|2] [-s ssap] [-d dsap] [-c count] [-i wait] [-p pattern] [-l len]\n", name_s);
	printf("	[-o retry:size:ack:p:reject:busy:txwin:rxwin] [-nxbfqwuz] source_host destination_host\n");
        exit(1);
}

/* fill in the outbound packet with custom data. */
void fill(struct llc_options *llc, void *bp1, char *patp)
{
        int pat[16], ii, jj, kk;    
        char *cp, *bp = (char *)bp1;
        
        for(cp = patp; *cp; cp++) {
                if(!isxdigit(*cp)) {
                        printf("%s: patterns must be specified as hex digits.\n",
				name_s);
                        exit(2);
                }
        }

        ii = sscanf(patp,
        	"%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
            	&pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
            	&pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
            	&pat[13], &pat[14], &pat[15]);

        if(ii > 0) {
                for(kk = 0; kk <= LLC_MAX_LEN - (8 + ii); kk += ii)
                        for(jj = 0; jj < ii; ++jj)
                                bp[jj + kk] = pat[jj];
        }

	if(!llc->quiet) {
                printf("PATTERN: 0x");
                for(jj = 0; jj < ii; ++jj)
                	printf("%02x", bp[jj] & 0xFF);
                printf("\n");
        }
}

/* subtract 2 timeval structs:  out = out - in.  out is assumed to be >= in. */
void tvsub(register struct timeval *out, register struct timeval *in)
{
        if((out->tv_usec -= in->tv_usec) < 0) {
                --out->tv_sec;
                out->tv_usec += 1000000;
        }
        out->tv_sec -= in->tv_sec;
}

/* display results of a single packet. */
void pr_pack(struct llc_options *llc, char *buf, int len, struct sockaddr_llc *from)
{
        struct timeval tv, *tp;
        long triptime = 0;
	char bspace = '\b';

        gettimeofday(&tv, (struct timezone *)NULL);
        ++llc->received;

        tp = (struct timeval *)buf;
        tvsub(&tv, tp);
        triptime = tv.tv_sec * 10000 + (tv.tv_usec / 100);
        llc->tsum += triptime;
        if(triptime < llc->tmin)
                llc->tmin = triptime;
        if(triptime > llc->tmax)
                llc->tmax = triptime;

	if(llc->quiet)
		return;
	if(llc->flood)
                write(STDOUT_FILENO, &bspace, 1);
        else {
		if(llc->type == LLC_TYPE_2)
			printf("%d bytes from %s:", len, pr_ether(llc->dst.sllc_mac,
				llc->numeric));
		else
	                printf("%d bytes from %s:", len, pr_ether(from->sllc_mac,
				llc->numeric));
                printf(" num=%d time=%ld.%ld ms\n", llc->received, 
			triptime / 10, triptime % 10);

		if(llc->hexdump)
			hexdump(buf, len);
        }
}

/* display stats and exit. */
void finish(int ignore)
{
	struct llc_options *llc = tmp_llc;

        (void)ignore;
        (void)signal(SIGINT, SIG_IGN);

        putchar('\n');
        fflush(stdout);
        printf("--- %s @ 0x%02X via LLC%d %s statistics ---\n",
                pr_ether(llc->dst.sllc_mac, llc->numeric), llc->dsap, 
		llc->type, name_s);
        printf("%d packets transmitted, ", llc->transmitted);
        printf("%d packets received, ", llc->received);
        if(llc->repeats)
        	printf("+%d duplicates, ", llc->repeats);
        if(llc->transmitted) {
                if(llc->received > llc->transmitted)
                        printf("-- somebody's printing up packets!");
                else
                        printf("%d%% packet loss",
                            (int)(((llc->transmitted - llc->received) * 100) /
                            llc->transmitted));
        }
        putchar('\n');
        if(llc->received && llc->timing) {
                printf("round-trip min/avg/max = %d.%d/%d.%d/%d.%d ms\n",
			llc->tmin / 10, llc->tmin % 10,
                        (llc->tsum / (llc->received + llc->repeats)) / 10,
                        (llc->tsum / (llc->received + llc->repeats)) % 10,
                        llc->tmax / 10, llc->tmax % 10);
        }

        if(llc->received == 0)
                exit(1);

        exit(0);
}

/* Compose and transmit an LLC TEST CMD packet. The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
void pinger(void)
{
	struct llc_options *llc = tmp_llc;
	char dot = '.';
        int i = 0, cc = 0;

        llc->transmitted++;

        gettimeofday((struct timeval *)&llc->outpacket[0],
            (struct timezone *)NULL);

	cc = llc->len;
	if(llc->type == LLC_TYPE_2) {
		if(llc->ua) {
			llc->dst.sllc_ua = 1;
			i = sendto(llc->sk, llc->outpacket, cc, 0,
                        	(struct sockaddr *)&llc->dst,
                        	sizeof(struct sockaddr_llc));
			llc->dst.sllc_ua = 0;
		} else {
			if(llc->test) {
				llc->dst.sllc_test = 1;
				i = sendto(llc->sk, llc->outpacket, cc, 0,
		                        (struct sockaddr *)&llc->dst,
		                        sizeof(struct sockaddr_llc));
                        	llc->dst.sllc_test = 0;
			} else {
				if(llc->xid) {
					llc->dst.sllc_xid = 1;
					i = sendto(llc->sk, llc->outpacket, cc,
						0, (struct sockaddr *)&llc->dst,
						sizeof(struct sockaddr_llc));
					llc->dst.sllc_xid = 0;
				} else {
					i = send(llc->sk, llc->outpacket, cc,0);
				}
			}
		}
	} else {
		if(llc->test)
			llc->dst.sllc_test = 1;
		if(llc->xid)
			llc->dst.sllc_xid = 1;
	        i = sendto(llc->sk, llc->outpacket, cc, 0, 
			(struct sockaddr *)&llc->dst, 
			sizeof(struct sockaddr_llc));
		if(llc->test)
                        llc->dst.sllc_test = 0;
		if(llc->xid)
			llc->dst.sllc_xid = 0;
	}
        if(i < 0 || i != cc) {
                if(i < 0)
                        printf("%s: sendto %s\n", name_s, strerror(errno));
                printf("%s: wrote %s %d chars, ret=%d\n", name_s,
                    pr_ether(llc->dst.sllc_mac, llc->numeric), cc, i);
        }
        if(!llc->quiet && llc->flood)
                write(STDOUT_FILENO, &dot, 1);
	else {
		if(llc->hexdump) {
			printf("%d bytes to %s:", llc->len, 
				pr_ether(llc->dst.sllc_mac, llc->numeric));
			printf(" num=%d time=0.0 ms\n", llc->received + 1);
	                hexdump(llc->outpacket, llc->len);
		}
	}
}

/* causes another PING to be transmitted, then schedules another
 * SIGALRM in 1 second from now.
 */
void catcher(int ignore)
{       
	struct llc_options *llc = tmp_llc;
        int waittime;
        
        (void)ignore;
        pinger();
        (void)signal(SIGALRM, catcher);
        if(!llc->count || llc->transmitted < llc->count)
                alarm((u_int)llc->wait);
        else {
                if(llc->received) {
                        waittime = 2 * llc->tmax / 1000;
                        if(!waittime)
                                waittime = 1;
                        if(waittime > LLC_MAX_INTERVAL)
                                waittime = LLC_MAX_INTERVAL;
                }
                else    
                        waittime = LLC_MAX_INTERVAL;
                (void)signal(SIGALRM, finish);
                (void)alarm((u_int)waittime);
        }
}

int main(int argc, char **argv)
{
	struct timeval timeout;
	struct llc_options *llc;
	int fdmask;
	int c, err;

	static char *null = NULL;
        __environ = &null;

	if(!new(llc))
		return (-ENOMEM);
	set_llc_defaults(llc);
	tmp_llc = llc;

	while((c = getopt(argc, argv, "hvVbxfqnwuzt:s:d:c:i:p:l:o:")) != EOF) {
                switch(c) {
                        case 'V':       /* Display author and version. */
                        case 'v':       /* Display author and version. */
				free(llc);
                                version();
                                break;

                        case 'h':       /* Display useless help information. */
				free(llc);
                                help();
				break;

			case 't':	/* type of llc socket to use. */
				llc->type = atoi(optarg);
				if(llc->type > LLC_TYPE_2) {
					free(llc);
					help();
				}
				break;

			case 'b':	/* bit swap destination address. */
				llc->flip = 1;
				break;

			case 's':	/* source sap to use. */
				llc->ssap = strtol(optarg, (char **)NULL, 0);
				break;

			case 'd':	/* destination sap to use. */
				llc->dsap = strtol(optarg, (char **)NULL, 0);
				break;

			case 'c':	/* number of packets to send. */
				llc->count = atoi(optarg);
				if(llc->count == 0) {
					printf("%s: number of packets to transmit (%d) invalid.\n",
						name_s, llc->count);
					free(llc);
					exit (2);
                        	}
				break;

			case 'i':	/* time between packets. */
				llc->wait = atoi(optarg);
				if(llc->wait == 0 || llc->wait > LLC_MAX_INTERVAL) {
					printf("%s: timing interval (%d) invalid.\n",
						name_s, llc->wait);
					free(llc);
					exit (2);
				}
				break;

			case 'p':	/* pattern to send. */
				llc->fill = 1;
				fill(llc, &llc->outpacket[sizeof(struct timeval)], optarg);
				break;

			case 'o':	/* llc socket options. */
				llc->options = 1;
				load_options(llc, optarg);
				break;

			case 'l':	/* length of packet. */
				llc->len = atoi(optarg);
				if(llc->len > LLC_MAX_LEN || llc->len < LLC_MIN_LEN) {
					printf("%s: packet size (%d) invalid.\n",
						name_s, llc->len);
					free(llc);
					exit (2);
				}
				break;

			case 'f':	/* flood ping. */
				if(!llc->is_root) {
					printf("%s: %s\n", name_s, strerror(EPERM));
					free(llc);
					exit (2);
				}
				llc->flood = 1;
				setbuf(stdout, NULL);
				break;

			case 'q':	/* quiet mode. */
				llc->quiet = 1;
				break;

			case 'x':	/* hexdump data. */
				llc->hexdump = 1;
				break;

			case 'n':	/* numeric output. */
				llc->numeric = 1;
				break;

			case 'u':	/* send ui frame over llc2. */
				llc->ua = 1;
				break;

			case 'w':	/* send xid frame over llc1/2. */
				llc->xid = 1;
				break;
				
			case 'z':	/* send test frame over llc1/2. */
				llc->test = 1;
				break;

			default:
				free(llc);
				help();
                }
	}

	argc -= optind;
	argv += optind;
	if(argc < 2) {
		free(llc);
		help();
	}

	err = in_ether(*argv, llc->smac, 0);		/* set source mac. */
	if(err < 0) {
		struct llchostent *lh;
		lh = getllchostbyname(*argv);
		if(!lh) {
			printf("%s: unknown host %s\n", name_s, *argv);
			exit (2);
		}
		memcpy(llc->smac, lh->lh_addr, lh->lh_length);
	}
	argc--, argv++;
	err = in_ether(*argv, llc->dmac, llc->flip);	/* set destination mac. */
	if(err < 0) {
		struct llchostent *lh;
                lh = getllchostbyname(*argv);
                if(!lh) {
			printf("%s: unknown host %s\n", name_s, *argv);
                        exit (2);
		}
                memcpy(llc->dmac, lh->lh_addr, lh->lh_length);
	}

	if(llc->flood && llc->wait > 1) {
                printf("%s: -f and -i incompatible options.\n", name_s);
		free(llc);
                exit (2);
        }

	if(!llc->fill) {
		int i;
		char *datap = &llc->outpacket[sizeof(struct timeval)];
		for(i = 8; i < llc->len; ++i)
                        *datap++ = i;
	}

	if(llc->len >= (int)sizeof(struct timeval))     /* can we tx time ? */
                llc->timing = 1;

	printf("%s: %s, %s\n", name_s, version_s, desc_s);
	if(setup_llc_socket(llc) < 0) {
		free(llc);
		exit (2);
	}

	if(llc->options && llc->type == LLC_TYPE_2)
		set_llc_sockopt(llc);
	if(llc->type == LLC_TYPE_2)
		printf("%s: opts @ %s\n", name_s, display_llc_sockopt(llc));

	printf("%s: %s @ 0x%02X via LLC%d: %d data bytes\n", name_s,
                pr_ether(llc->smac, llc->numeric), llc->ssap, llc->type, llc->len);

        (void)signal(SIGINT, finish);
        (void)signal(SIGALRM, catcher);

	if(!llc->flood)
		catcher(0);	/* start the process. */
	for(;;) {
                struct sockaddr_llc from;
                size_t fromlen;
		int cc, packlen;
		char *packet;

                if(llc->count && llc->received >= llc->count)
                        break;

		packlen = llc->len;
        	packet = new_s(packlen);
        	if(!packet) {
                	printf("%s: out of memory.\n", name_s);
                	free(llc);
                	exit (2);
        	}

                if(llc->flood ){
                        pinger();
                        timeout.tv_sec = 0;
                        timeout.tv_usec = 900000;
                        fdmask = 1 << llc->sk;
                        if(select(llc->sk + 1, (fd_set *)&fdmask, (fd_set *)NULL,
                        	(fd_set *)NULL, &timeout) < 1)
                                continue;
                }
		if(llc->type == LLC_TYPE_2) {
			cc = recv(llc->sk, packet, packlen, 0);
		} else {
	                fromlen = sizeof(from);
	                cc = recvfrom(llc->sk, packet, packlen, 0,
	                	(struct sockaddr *)&from, &fromlen);
		}
		if(cc < 0) {
			if(errno == EINTR)
				continue;
                        printf("%s: recvfrom `%s'\n", name_s, strerror(errno));
			if(errno == ENOTCONN)
				break;
                        continue;
		}

                pr_pack(llc, (char *)packet, cc, &from);
		free(packet);
        }
        finish(0);

	return (0);
}
