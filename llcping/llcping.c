/* llcping.c: Linux LLC Ping Client utility.
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
#include <dlfcn.h>
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

/* our stuff. */
#include "llcping.h"

#ifndef AF_LLC
#define AF_LLC          22
#define PF_LLC          AF_LLC
#endif

char version_s[]                        = VERSION;
char name_s[]                           = "llcping";
char desc_s[]                           = "IEEE 802.2 llc echo client";
char maintainer_s[]                     = "Jay Schulist <jschlst@samba.org>";

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

char *pr_ether(char *ptr)
{
	static char buff[64];

        snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X",
                (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
                (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
        return(buff);
}

int hexdump(unsigned char *pkt_data, int pkt_len)
{
        int i;

        while(pkt_len>0) {
                printf("   ");   /* Leading spaces. */

                /* Print the HEX representation. */
                for(i=0; i<8; ++i) {
                        if(pkt_len - (long)i>0)
                                printf("%2.2X ", pkt_data[i] & 0xFF);
                        else
                                printf("  ");
                }

                printf(":");

                for(i=8; i<16; ++i) {
                        if(pkt_len - (long)i>0)
                                printf("%2.2X ", pkt_data[i]&0xFF);
                        else
                                printf("  ");
                }

                /* Print the ASCII representation. */
                printf("  ");

                for(i=0; i<16; ++i) {
                        if(pkt_len - (long)i>0) {
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
    	while((*bufp != '\0') && (i < ETH_ALEN)) 
	{
        	val = 0;
        	c = *bufp++;
        	if(isdigit(c))
            		val = c - '0';
        	else if(c >= 'a' && c <= 'f')
            		val = c - 'a' + 10;
        	else if(c >= 'A' && c <= 'F')
            		val = c - 'A' + 10;
        	else 
		{
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
        	else 
		{
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
	if(llc->sk < 0)
	{
		if(errno == EPERM)
			printf("%s: must run as root.\n", name_s);
		else
			printf("%s: socket %s.\n", name_s, strerror(llc->sk));
		return (llc->sk);
	}

	to = &llc->dst;
	to->sllc_family	= PF_LLC;
	to->sllc_arphrd = ARPHRD_ETHER;
	to->sllc_test	= 0;
	to->sllc_xid	= 0;
	to->sllc_ua	= 0;
	to->sllc_dsap	= llc->dsap;
	to->sllc_ssap	= llc->ssap;
	memcpy(&to->sllc_dmac, &llc->dmac, IFHWADDRLEN);
	memcpy(&to->sllc_smac, &llc->smac, IFHWADDRLEN);
	if(llc->type == LLC_TYPE_NULL)
		to->sllc_test = 1;

	err = bind(llc->sk, (struct sockaddr *)&llc->dst, 
		sizeof(struct sockaddr_llc));
	if(err < 0)
	{
		printf("%s: bind %s.\n", name_s, strerror(err));
		close(llc->sk);
		return (err);
	}

	if(sk_type != SOCK_STREAM)
		return (0);

	err = connect(llc->sk, (struct sockaddr *)&llc->dst, 
		sizeof(struct sockaddr_llc));
	if(err < 0)
	{
		printf("%s: connect %s.\n", name_s, strerror(err));
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
        exit(1);
}       

/* display useless help. */ 
void help(void)
{
        printf("Usage: %s [-h] [-v] [-t 1|2] [-s ssap] [-d dsap] [-c count] [-i wait]\n", name_s);
	printf("	[-p pattern] [-l len] [-xbfq] SR:CM:AC:AD:DR:ES DS:TM:AC:AD:DR:ES\n");
        exit(1);
}

/* fill in the outbound packet with custom data. */
void fill(struct llc_options *llc, void *bp1, char *patp)
{
        int pat[16], ii, jj, kk;    
        char *cp, *bp = (char *)bp1;
        
        for(cp = patp; *cp; cp++)
        {
                if(!isxdigit(*cp))
                {
                        (void)fprintf(stderr,
                            "llcping: patterns must be specified as hex digits.\n");
                        exit(2);
                }
        }

        ii = sscanf(patp,
        	"%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
            	&pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5], &pat[6],
            	&pat[7], &pat[8], &pat[9], &pat[10], &pat[11], &pat[12],
            	&pat[13], &pat[14], &pat[15]);

        if(ii > 0)
        {
                for(kk = 0; kk <= LLC_MAX_LEN - (8 + ii); kk += ii)
                        for(jj = 0; jj < ii; ++jj)
                                bp[jj + kk] = pat[jj];
        }

	if(!llc->quiet)
        {
                printf("PATTERN: 0x");
                for(jj = 0; jj < ii; ++jj)
                	printf("%02x", bp[jj] & 0xFF);
                printf("\n");
        }
}

/* subtract 2 timeval structs:  out = out - in.  out is assumed to be >= in. */
void tvsub(register struct timeval *out, register struct timeval *in)
{
        if((out->tv_usec -= in->tv_usec) < 0)
        {
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
        else
        {
                printf("%d bytes from %s:", len, pr_ether(from->sllc_smac));
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
                pr_ether(llc->dst.sllc_dmac), llc->dsap, llc->type, name_s);
        printf("%d packets transmitted, ", llc->transmitted);
        printf("%d packets received, ", llc->received);
        if(llc->repeats)
        	printf("+%d duplicates, ", llc->repeats);
        if(llc->transmitted)
        {
                if(llc->received > llc->transmitted)
                        printf("-- somebody's printing up packets!");
                else
                        printf("%d%% packet loss",
                            (int)(((llc->transmitted - llc->received) * 100) /
                            llc->transmitted));
        }
        putchar('\n');
        if(llc->received && llc->timing)
        {
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
        int i, cc;

        llc->transmitted++;

        gettimeofday((struct timeval *)&llc->outpacket[0],
            (struct timezone *)NULL);

	cc = llc->len;
        i = sendto(llc->sk, (char *)llc->outpacket, cc, 0, (struct sockaddr *)&llc->dst,
            sizeof(struct sockaddr_llc));

        if(i < 0 || i != cc)
        {
                if(i < 0)
                        printf("%s: sendto %s", name_s, strerror(i));
                printf("%s: wrote %s %d chars, ret=%d\n", name_s,
                    pr_ether(llc->dst.sllc_dmac), cc, i);
        }
        if(!llc->quiet && llc->flood)
                write(STDOUT_FILENO, &dot, 1);
	else
	{
		if(llc->hexdump)
		{
			printf("%d bytes to %s:", llc->len, pr_ether(llc->dst.sllc_dmac));
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
        else
        {       
                if(llc->received)
                {       
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
	int c;

	static char *null = NULL;
        __environ = &null;

	if(!new(llc))
		return (-ENOMEM);
	set_llc_defaults(llc);
	tmp_llc = llc;

	while((c = getopt(argc, argv, "hvVbxfqt:s:d:c:i:p:l:")) != EOF)
        {
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
				if(llc->type > LLC_TYPE_2) 
				{
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
				if(llc->count == 0)
				{
					printf("%s: number of packets to transmit (%d) invalid.\n",
						name_s, llc->count);
					free(llc);
					exit (2);
                        	}
				break;

			case 'i':	/* time between packets. */
				llc->wait = atoi(optarg);
				if(llc->wait == 0 || llc->wait > LLC_MAX_INTERVAL)
				{
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

			case 'l':	/* length of packet. */
				llc->len = atoi(optarg);
				if(llc->len > LLC_MAX_LEN || llc->len < LLC_MIN_LEN)
				{
					printf("%s: packet size (%d) invalid.\n",
						name_s, llc->len);
					free(llc);
					exit (2);
				}
				break;

			case 'f':	/* flood ping. */
				if(!llc->is_root)
				{
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

			default:
				free(llc);
				help();
                }
	}

	argc -= optind;
	argv += optind;
	if(argc < 2)
	{
		free(llc);
		help();
	}

	in_ether(*argv, llc->smac, 0);		/* set source mac. */
	argc--, argv++;
	in_ether(*argv, llc->dmac, llc->flip);	/* set destination mac. */

	if(llc->flood && llc->wait > 1)
        {
                printf("%s: -f and -i incompatible options.\n", name_s);
		free(llc);
                exit(2);
        }

	if(!llc->fill)
	{
		int i;
		char *datap = &llc->outpacket[sizeof(struct timeval)];
		for(i = 8; i < llc->len; ++i)
                        *datap++ = i;
	}

	if(llc->len >= (int)sizeof(struct timeval))     /* can we tx time ? */
                llc->timing = 1;

	printf("%s: %s, %s\n", name_s, version_s, desc_s);
	printf("%s: %s @ 0x%02X via LLC%d: %d data bytes\n", name_s,
		pr_ether(llc->smac), llc->ssap, llc->type, llc->len);

	if(setup_llc_socket(llc) < 0)
	{
		free(llc);
		exit (2);
	}

        (void)signal(SIGINT, finish);
        (void)signal(SIGALRM, catcher);

	if(!llc->flood)
		catcher(0);	/* start the process. */
	for(;;)
        {
                struct sockaddr_llc from;
                size_t fromlen;
		int cc, packlen;
		char *packet;

                if(llc->count && llc->received >= llc->count)
                        break;

		packlen = llc->len;
        	packet = new_s(packlen);
        	if(!packet)
        	{
                	printf("%s: out of memory.\n", name_s);
                	free(llc);
                	exit(2);
        	}

                if(llc->flood)
                {
                        pinger();
                        timeout.tv_sec = 0;
                        timeout.tv_usec = 900000;
                        fdmask = 1 << llc->sk;
                        if(select(llc->sk + 1, (fd_set *)&fdmask, (fd_set *)NULL,
                        	(fd_set *)NULL, &timeout) < 1)
                                continue;
                }
                fromlen = sizeof(from);
                if((cc = recvfrom(llc->sk, (char *)packet, packlen, 0,
                    (struct sockaddr *)&from, &fromlen)) < 0)
                {
                        if(errno == EINTR)
                                continue;
                        perror("llcping: recvfrom");
                        continue;
                }

                pr_pack(llc, (char *)packet, cc, &from);
		free(packet);
        }
        finish(0);

	return (0);
}
