/* llcpingd.c: Linux LLC Ping Server utility.
 * Copyright (c) 2000, Jay Schulist.
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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/llc.h>

char ToolsVersion[] = VERSION;
char ToolsMaintain[] = "Jay Schulist <jschlst@samba.org>";

#ifndef LLC_PING_SAP
#define LLC_PING_SAP	0x88
#endif
unsigned char default_ssap = LLC_PING_SAP;

#ifndef AF_LLC
#define AF_LLC	22
#endif

#define PF_LLC          AF_LLC

struct llchdr {
        unsigned char dsap;
        unsigned char ssap;
        unsigned char ctrl;
};

#define LLC_CTRL_TEST_CMD	0xF3
#define LLC_CTRL_TEST_RSP	0xF3

/*
 * Note: on some systems dropping root makes the process dumpable or
 * traceable. In that case if you enable dropping root and someone
 * traces ping, they get control of a raw socket and can start
 * spoofing whatever packets they like. SO BE CAREFUL.
 */

static time_t last_time;

#define LLC_MINLEN	(3 + 8)

#define	DEFDATALEN	64 	/* default data length */
#define	MAXPACKET	(65535 - 3)/* max packet size */
#define	MAXWAIT		10		/* max seconds to wait for response */

#define	A(bit)		rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	SET(bit)	(A(bit) |= B(bit))
#define	CLR(bit)	(A(bit) &= (~B(bit)))
#define	TST(bit)	(A(bit) & B(bit))

/* various options */
int options;
#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100

/* multicast options */
int moptions;
#define MULTICAST_NOLOOP	0x001
#define MULTICAST_TTL		0x002
#define MULTICAST_IF		0x004

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.  Change 128
 * to 8192 for complete accuracy...
 */
#define	MAX_DUP_CHK	(8 * 128)
int mx_dup_ck = MAX_DUP_CHK;
char rcvd_tbl[MAX_DUP_CHK / 8];

struct sockaddr_llc whereto;	/* who to ping */
int datalen = DEFDATALEN;
int s;				/* socket file descriptor */
u_char outpack[MAXPACKET];
char BSPACE = '\b';		/* characters written for flood */
char DOT = '.';
static char hostname[20];
static int ident;		/* process id to identify our packets */
int flip_dest = 0;		/* should dest mac addr be bit fliped */
int use_llc_type = 1;		/* what llc type to use. */
int use_mac_addr = 0;

/* counters */
static long npackets;		/* max packets to transmit */
static long nreceived;		/* # of packets we got back */
static long nrepeats;		/* number of duplicates */
static long ntransmitted;	/* sequence # for outbound packets = #sent */
static int interval = 1;	/* interval between packets */

/* timing */
static int timing;		/* flag to do timing */
static long tmin = LONG_MAX;	/* minimum round trip time */
static long tmax = 0;		/* maximum round trip time */
static u_long tsum;		/* sum of all times, for doing average */

/* protos */
static void usage(void);

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


/* Input an Ethernet address and convert to binary. Save in sap->sa_dst; */
static int in_ether(char *bufp, struct sockaddr_llc *sap, int w, int f)
{
    unsigned char *ptr;
    char c, *orig;
    int i;
    unsigned val;

    if(w == 1)	/* Dst */
    	ptr = sap->sllc_dmac;
    else	/* Src */
	ptr = sap->sllc_smac;

    i = 0;
    orig = bufp;
    while ((*bufp != '\0') && (i < ETH_ALEN)) {
        val = 0;
        c = *bufp++;
        if (isdigit(c))
            val = c - '0';
        else if (c >= 'a' && c <= 'f')
            val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            val = c - 'A' + 10;
        else {
            errno = EINVAL;
            return (-1);
        }
        val <<= 4;
        c = *bufp;
        if (isdigit(c))
            val |= c - '0';
        else if (c >= 'a' && c <= 'f')
            val |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            val |= c - 'A' + 10;
        else if (c == ':' || c == 0)
            val >>= 4;
        else {
            errno = EINVAL;
            return (-1);
        }
        if (c != 0)
            bufp++;
	if(f)
		*ptr++ = flip_byte((unsigned char) (val & 0377));
	else
        	*ptr++ = (unsigned char) (val & 0377);
        i++;

        /* We might get a semicolon here - not required. */
        if (*bufp == ':') {
            if (i == ETH_ALEN) {
                    ;           /* nothing */
            }
            bufp++;
        }
    }

    return (0);
}

int version(void)
{
        printf("%s%s\n", "llcpingd v", ToolsVersion);
        printf("%s\n", ToolsMaintain);

        exit (1);
}

int main(int argc, char *argv[])
{
	struct timeval timeout;
	struct sockaddr_llc *to, me;
	int i, stype, s2;
	int ch, fdmask, hold, packlen, preload;
	u_char *datap, *packet;
	char *target, *from;
	int am_i_root;
	fd_set all_fds, readable;
	int fd, highest_fd = 0;

	static char *null = NULL;
	__environ = &null;
	am_i_root = (getuid()==0);

	/* setup last_time to be current time -1 second */
	time(&last_time);
	last_time--;

	setuid(getuid());
	preload = 0;
	datap = &outpack[sizeof(struct timeval)];
	while ((ch = getopt(argc, argv, "2hvsm")) != EOF)
	{
		switch(ch) {
		case '2':
			use_llc_type = 2;
			break;

		case 'h':
			usage();

		case 'v':
			version();

		case 's':
			default_ssap = strtol(argv[optind++], (char **)NULL, 0);
			break;

		case 'm':
			use_mac_addr = 1;
			break;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if(argc == 0)
		usage();

	memset(&whereto, 0, sizeof(struct sockaddr_llc));
        to = (struct sockaddr_llc *)&whereto;
	to->sllc_family = AF_LLC;
	to->sllc_arphrd = ARPHRD_ETHER;
	to->sllc_test	= 0;
	to->sllc_xid	= 0;
	to->sllc_dsap	= 0x0;
	to->sllc_ssap	= default_ssap;

	/* Get destination and source address from user */
	from = *argv;
	in_ether(from, to, 2, 0);
	argc--;
        argv++;

	sprintf(hostname, "%02X:%02X:%02X:%02X:%02X:%02X",
                to->sllc_smac[0], to->sllc_smac[1], to->sllc_smac[2],
                to->sllc_smac[3], to->sllc_smac[4], to->sllc_smac[5]);

	if(use_llc_type == 2)
		stype = SOCK_STREAM;
	else
		stype = SOCK_DGRAM;
	if((s = socket(PF_LLC, stype, 0)) < 0)
        {
                if(errno == EPERM)
                        fprintf(stderr, "llcpingd: ping must run as root\n");
                else
                        perror("llcpingd: socket");
                exit(2);
        }

	memset(&me, 0, sizeof(me));
	me.sllc_family 	= AF_LLC;
	me.sllc_ssap	= default_ssap;
	if(use_mac_addr)
	{
		me.sllc_arphrd = ARPHRD_ETHER;
		memcpy(me.sllc_smac, to->sllc_smac, 6);
	}
	if(bind(s, (struct sockaddr *)&me, sizeof(me)))
	{
		perror("llcpingd: bind");
		exit (2);
	}

	FD_ZERO(&all_fds);
	if(listen(s, 10) < 0)
	{
		perror("llcpingd: listen");
		exit (2);
	}
	FD_SET(s, &all_fds);
	highest_fd = s;

	ident = getpid() & 0xFFFF;
	hold = 1;

	printf("LLCPINGD v%s, LLC PING DAEMON for Linux.\n", ToolsVersion);
	printf("LLCPINGD - %s @ 0x%02X via LLC%d: listening\n", 
		hostname, default_ssap, use_llc_type);

	for(;;)
	{
		struct sockaddr_llc from, loop;
		register int cc;
		size_t fromlen;
		int i;

		readable = all_fds;

//		printf("highest_fd %d\n", highest_fd);

		fd = select(highest_fd + 1, &readable, NULL, NULL, NULL);
		if(fd < 0)
		{
                        if(fd < 0 && errno != EINTR)
                        {
                                printf("select failed: %s",
                                        strerror(errno));
                                sleep(1);
                        }
			printf("less than 0\n");
                        continue;
                }

		/* find which fd has an event for us. */
                for(i = 0; i <= highest_fd; i++)
                {
                        if(FD_ISSET(i, &readable))
                        {
                                if(s == i)
                                {
					int new_conn = 0;
					fromlen = sizeof(from);
					new_conn = accept(s, (struct sockaddr *)&from, &fromlen);
					if(new_conn < 0)
					{
						printf("accept error\n");
						continue;
					}
					printf("client (%d) connected\n", new_conn);
					FD_SET(new_conn, &all_fds);
					if(new_conn > highest_fd)
						highest_fd = new_conn;
                                        continue;
                                }

				/* any other fd is a client. */
				packlen = 8192;
		        	packet = malloc((u_int)packlen);
		        	if(!packet)
		        	{
		        	        (void)fprintf(stderr, "llcpingd: out of memory.\n");
		        	        exit(2);
		        	}

				memset(&from, 0, sizeof(from));
				fromlen = sizeof(from);
				if((cc = recvfrom(i, (char *)packet, packlen, 0,
				    (struct sockaddr *)&from, &fromlen)) < 0)
				{
					if(errno == EINTR)
						continue;
					/* client disconnect. */
					printf("client (%d) disconnected\n", i);
					close(i);
					FD_CLR(i, &all_fds);
					continue;
				}

#ifdef NOT
				printf("(%d): RX: %02X:%02X:%02X:%02X:%02X:%02X @ 0x%02X"
					" -> %02X:%02X:%02X:%02X:%02X:%02X @ 0x%02X\n", i,
			                from.sllc_smac[0], from.sllc_smac[1], from.sllc_smac[2],
			                from.sllc_smac[3], from.sllc_smac[4], from.sllc_smac[5],
					from.sllc_ssap,
					from.sllc_dmac[0], from.sllc_dmac[1], from.sllc_dmac[2],
		                        from.sllc_dmac[3], from.sllc_dmac[4], from.sllc_dmac[5],
		                        from.sllc_dsap);
#endif
				memcpy(&loop, &from, sizeof(from));
				memcpy(loop.sllc_dmac, from.sllc_smac, IFHWADDRLEN);
				memcpy(loop.sllc_smac, from.sllc_dmac, IFHWADDRLEN);
				loop.sllc_dsap = from.sllc_ssap;
				loop.sllc_ssap = from.sllc_dsap;

				(void) sendto(i, packet, cc, 0, (struct sockaddr *)&loop, 
					sizeof(loop));
				free(packet);
				continue;
			}
		}
	}

	return 0;
}

static void usage(void)
{
	(void)fprintf(stderr,
	    "Usage: llcpingd [-2hv] [-s 0xsap] SR:CM:AC:AD:DR:ES\n");

	exit(2);
}
