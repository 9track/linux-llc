/* lard.c: lan address resolution daemon.
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
#include "lar.h"
#include "lar_unix.h"
#include "llookup.h"

char version_s[]                        = VERSION;
char name_s[]                           = "llookup";
char desc_s[]                           = "Lan address resolution lookup client";
char maintainer_s[]                     = "Jay Schulist <jschlst@samba.org>";

static struct wordmap rtcap_types[] = {
        { "subarea",            0x40    },
        { "appn",               0x80    },
        { "name",               0xAA    },
        { NULL,         -1              }
};

static lar_snpa_t **make_array_snpa(struct llookup_options *lar)
{
	struct llookup_snpa *slist;
	static lar_snpa_t *sargv[LAR_MAX_SV_GROUP_NAMES];
	int i;

	i = 0;
	for(slist = lar->snpa; slist != NULL; slist = slist->next) {
		sargv[i] = &slist->a;
		i++;
	}
	sargv[++i] = NULL;

	return (sargv);
}

static u_int8_t **make_array_group(struct llookup_options *lar)
{
	struct llookup_group *glist;
	static u_int8_t *gargv[LAR_MAX_SV_GROUP_NAMES];
	int i;

	i = 0;
	for(glist = lar->group; glist != NULL; glist = glist->next) {
		gargv[i] = glist->g;
		i++;
	}
	gargv[++i] = NULL;

	return (gargv);
}

static struct llookup_netid *char_to_netid(unsigned char *b) 
{       
        struct llookup_netid *n;
        unsigned char c[40];
        int i; 

        strcpy(c, b);   /* always use protection */
	if(!new(n))
		return (NULL);
        strcpy(n->name, strpbrk(c, ".")+1);
        for(i = 0; i < 8; i++)
                n->name[i] = toupper(n->name[i]);
	for(i = strlen(n->name); i < 8; i++)
                n->name[i] = 0x20;
        strcpy(n->net, strtok(c, "."));
        for(i = 0; i < 8; i++)
                n->net[i] = toupper(n->net[i]);
	for(i = strlen(n->net); i < 8; i++)
                n->net[i] = 0x20;
        return (n);
}

static char *netid_to_char(struct llookup_netid *n)
{
	static char c[20];
        int len = 0, i;

        for(i = 0; i < 8 && (n->net[i] != 0x20); i++)
                /* Nothing */ ;
        len = i;
        strncpy(c, n->net, i);
        len = i + 1;
        strncpy(c + i, ".", 1);
        for(i = 0; i < 8 && (n->name[i] != 0x20); i++)
                /* Nothing */ ;
        strncpy(c + len, n->name, i);
        len += i;
        strncpy(c + len, "\0", 1);

        return (c);
}

static char *pr_group(char *n)
{
	static char c[20];
	int len = 0, i;

	for(i = 0; i < 8 && (n[i] != 0x20); i++)
                /* Nothing */ ;
        len = i;
	strncpy(c, n, i);
	strncpy(c + len, "\0", 1);

        return (c);
}

static int get_and_set_hwaddr(u_int8_t *name, u_int8_t *hwaddr)
{
        struct ifreq req;
        int fd;

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

static int parse_group(struct llookup_options *lar, u_int8_t *data)
{
	struct llookup_group *group;

	if(strlen(data) <= 0 || strlen(data) > 8)
		return (-EINVAL);

	if(!new(group))
		return (-ENOMEM);

	strcpy(group->g, data);
	group->next	= lar->group;
	lar->group	= group;
	return (0);
}

static int parse_snpa(struct llookup_options *lar, u_int8_t *data)
{
	char *device, *start, *sbuf;
	struct llookup_snpa *snpa;
	u_int8_t lsap = 0;
	int i;

	if(strlen(data) <= 0)
		return (-EINVAL);

	sbuf = new_s(strlen(data));
	if(!sbuf)
		return (-ENOMEM);
	strcpy(sbuf, data);

	i = 0;
	start = (void *)strtok(sbuf, "@");
	do {
		switch(i) {
			case (0):	/* device or mac. */
				device = new_s(strlen(start));
				if(!device)
					return (-ENOMEM);
				strcpy(device, start);
				break;

			case (1):	/* lsap. */
				lsap = strtol(start, (char **)NULL, 0);
				break;
		}
		i++;
	} while((start = (void *)strtok(NULL, "@")) != NULL);

	if(!new(snpa))
		return (-ENOMEM);
	if(get_and_set_hwaddr(device, snpa->a.mac) < 0)
		return (-EINVAL);
	snpa->a.lsap = lsap;

	snpa->next	= lar->snpa;
	lar->snpa	= snpa;	

	free(device);
	free(sbuf);
	return (0);
}

static int map_word(struct wordmap *wm, const char *word)
{
        int i;
        for(i = 0; wm[i].word != NULL; i++)
                if(!strcmp(wm[i].word, word))
                        return (wm[i].val);

        return (-1);
}

static char *pr_word(struct wordmap *wm, const int v)
{
        int i;
        for(i = 0; wm[i].word != NULL; i++)
                if(wm[i].val == v)
                        return(wm[i].word);

        return (NULL);
}

static int set_lar_defaults(struct llookup_options *lar)
{
	if(!lar)
		return (-EINVAL);
	lar->snpa 	= NULL;
	lar->group	= NULL;
	return (0);
}

static char *pr_ether(char *ptr)
{
        static char buff[64];

        snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X",
                (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
                (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
        return(buff);
}

static char *print_lookup_options(struct llookup_options *lar)
{
	static char buf[3000];
	int len = 0;

	switch(lar->type) {
		case (LAR_UNIX_RECORD): {
			struct llookup_snpa *s;
			struct llookup_group *g;
			int i;

			len += sprintf(buf + len, "record: ");
			len += sprintf(buf + len, "%s ", netid_to_char(&lar->netid));
			len += sprintf(buf + len, "[%s] ", pr_word(rtcap_types, lar->rtcap));
			for(g = lar->group, i = 0; g != NULL; g = g->next, i++) {
                                len += sprintf(buf + len, "%s ", pr_group(g->g));
                        }
			len += sprintf(buf + len, "\n");

			/* display array of snpa. */
			for(s = lar->snpa, i = 0; s != NULL; s = s->next, i++) {
				if(!(i % 2))
					len += sprintf(buf + len, "        ");
				len += sprintf(buf + len, "%s@0x%02X ", 
					pr_ether(s->a.mac), s->a.lsap);
				if(i % 2 && s->next != NULL)
					len += sprintf(buf + len, "\n");
			}
			break;
		}

		case (LAR_UNIX_ERASE): {
			len += sprintf(buf + len, "erase: ");
			len += sprintf(buf + len, "%s ", netid_to_char(&lar->netid));
			break;
		}

		case (LAR_UNIX_SEARCH):
			len += sprintf(buf + len, "search: ");
			len += sprintf(buf + len, "%s for %s and %s capabilities", 
				lar->netid.net, lar->group->g,
				pr_word(rtcap_types, lar->rtcap));
			break;

		case (LAR_UNIX_FIND):
			len += sprintf(buf + len, "find: ");
			len += sprintf(buf + len, "%s ", netid_to_char(&lar->netid));
			break;

		case (LAR_UNIX_FIND_MEMBER):
			len += sprintf(buf + len, "find_member: ");
			len += sprintf(buf + len, "%s for %s and %s capabilities",
                                lar->netid.net, lar->group->g,
                                pr_word(rtcap_types, lar->rtcap));
			break;

		default:
			len += sprintf(buf + len, "unknown: %d ", lar->type);
			break;
	}

	return (buf);
}

/* display the applications version and information. */
static void version(void)
{       
        printf("%s: %s %s\n%s\n", name_s, desc_s, version_s,
                maintainer_s);
        exit(1);
}

/* display useless help. */
static void help(void)
{       
        printf("Usage: %s [-h] [-v] [-adfms] [-r subarea|appn|name] [-g group] [-n dev@sap] [netid.name]\n", name_s); 
        exit(1);
}

int main(int argc, char **argv)
{
	struct llookup_options *lar;
	int c, err;

	if(!new(lar))
		return (-ENOMEM);
	set_lar_defaults(lar);

	while((c = getopt(argc, argv, "hvVadfmsr:g:n:")) != EOF) {
                switch(c) {
                        case 'V':       /* display author and version. */
                        case 'v':       /* display author and version. */
                                version();
                                break;

                        case 'h':       /* display useless help information. */
                                help();
                                break;

			case 'a':	/* add or record lar entry. */
				lar->type = LAR_UNIX_RECORD;
				break;

			case 'd':	/* delete or erase lar entry. */
				lar->type = LAR_UNIX_ERASE;
				break;

			case 'f':	/* find lar entry. */
				lar->type = LAR_UNIX_FIND;
				break;

			case 'm':	/* find lar members. */
				lar->type = LAR_UNIX_FIND_MEMBER;
				break;

			case 's':	/* search lar members. */
				lar->type = LAR_UNIX_SEARCH;
				break;

			case 'r':	/* routing capabilities. */
				lar->rtcap = map_word(rtcap_types, optarg);
				break;

			case 'g':	/* group name. */
				parse_group(lar, optarg);
				break;

			case 'n':	/* service network point of attach. */
				parse_snpa(lar, optarg);
				break;

			default:
                                help();
                }
        }

	argc -= optind;
        argv += optind; 

	if(lar->type == LAR_UNIX_RECORD) {
		if(argc < 1) {
			free(lar);
			help();
		}
		memcpy(&lar->netid, char_to_netid(*argv), sizeof(struct llookup_netid));

		printf("%s\n", print_lookup_options(lar));
		err = lar_record(lar->netid.net, lar->netid.name, lar->rtcap, 
			make_array_snpa(lar), make_array_group(lar));
		if(err < 0)
			printf("record: completed with error `%s'.\n", strerror(errno));
		else
			printf("record: completed with no error.\n");
		goto out;
	}

	if(lar->type == LAR_UNIX_ERASE) {
		if(argc < 1) {
			free(lar);
			help();
		}
		memcpy(&lar->netid, char_to_netid(*argv), sizeof(struct llookup_netid));

		printf("%s\n", print_lookup_options(lar));
		err = lar_erase(lar->netid.net, lar->netid.name);
		if(err < 0)     
                        printf("erase: completed with error `%s'.\n", strerror(errno));
                else
                        printf("erase: completed with no error.\n");
		goto out;
	}

	if(lar->type == LAR_UNIX_SEARCH) {
		if(argc < 1) {
                        free(lar);
                        help();
                }
                memcpy(&lar->netid.net, *argv, strlen(*argv));

                printf("%s\n", print_lookup_options(lar));
                err = lar_search(lar->netid.net, lar->group->g, lar->rtcap, NULL);
                if(err < 0)
                        printf("search: completed with error `%s'.\n", strerror(errno));
                else
                        printf("search: completed with no error.\n");
                goto out;
	}

	if(lar->type == LAR_UNIX_FIND) {
		if(argc < 1) {
                        free(lar);
                        help();
                }
		memcpy(&lar->netid, char_to_netid(*argv), sizeof(struct llookup_netid));
                
                printf("%s\n", print_lookup_options(lar));
                err = lar_find(lar->netid.net, lar->netid.name, NULL);
                if(err < 0)
                        printf("find: completed with error `%s'.\n", strerror(errno));
                else
                        printf("find: completed with no error.\n");
                goto out;
	}

	if(lar->type == LAR_UNIX_FIND_MEMBER) {
		if(argc < 1) {
                        free(lar);
                        help();
                }
		memcpy(&lar->netid.net, *argv, strlen(*argv));
                
                printf("%s\n", print_lookup_options(lar));
                err = lar_find_member(1, lar->netid.net, lar->group->g, 
			lar->rtcap, NULL);
                if(err < 0)
                        printf("find_member: completed with error `%s'.\n", strerror(errno));
                else
                        printf("find_member: completed with no error.\n");
                goto out;
	}

	/* catch all. */
	free(lar);
	help();

out:	free(lar);
	return (0);
}
