/* dlsw_load.c: load a DataLinkSwitch configuration file.
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
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* required for llc sockets. */
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/llc.h>

/* our stuff. */
#include <dlsw_list.h>
#include <dlsw_ssp.h>
#include <dlsw_vector.h>
#include <dlswd_load.h>
#include <dlswd.h>

#include <gnome-xml/xmlmemory.h>
#include <gnome-xml/parser.h>

static global *ginfo = NULL;
extern global *dlsw_config_info;
extern struct dlsw_statistics *dlsw_stats;

extern char version_s[];
extern char name_s[];
extern char desc_s[];
extern char maintainer_s[];

struct wordmap dir_types[] = {
	{ "in",		0		},
	{ "out",	1		},
	{ NULL,		-1		}
};

struct wordmap on_types[] = {
        { "off",        0               },
        { "on",         1               },
        { NULL,         -1              }
};

struct wordmap yes_types[] = {
	{ "no",		0,		},
	{ "yes",	1,		},
	{ NULL,		-1,		}
};

int map_word(struct wordmap *wm, const char *word)
{
        int i;
        for (i = 0; wm[i].word != NULL; i++) {
                if (!strcmp(wm[i].word, word))
                        return (wm[i].val);
	}
        return -1;
}

char *pr_ether(char *ptr)
{
        static char buff[64];

        snprintf(buff, sizeof(buff), "%02X:%02X:%02X:%02X:%02X:%02X",
                (ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
                (ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));
        return(buff);
}

int dlsw_print_global(global *g)
{
	struct list_head *ent;
	struct dlsw_listen_info *l;
	struct dlsw_partner_info *p;
	struct dlsw_ssp_info *s;
	
        printf("\n================ Global Input Structure ================\n");

        if (!g) {
                printf("Global data is NULL!\n");
                goto pr_done;
        }

        printf("debug_level: %d\n", g->debug_level);

	printf("------------listen-------------\n");
	list_for_each(ent, &g->listen_list) {
		char sp_buf[1000], np_buf[1000];
		int i, len = 0;

		memset(sp_buf, '\0', sizeof(sp_buf));
		memset(np_buf, '\0', sizeof(np_buf));
		l = list_entry(ent, struct dlsw_listen_info, list);
		len = 0;
		for (i = 0; l->sna_sap_list[i] != NULL; i++)
			len += sprintf(sp_buf + len, "0x%02x ", l->sna_sap_list[i]);
		len = 0;
		for (i = 0; l->netbios_sap_list[i] != NULL; i++)
			len += sprintf(np_buf + len, "0x%02X ", l->netbios_sap_list[i]);

		printf("iface (%s) sna (%d) netbios (%d)\n", l->ifname, l->sna, l->netbios);
		printf("sna_port_list = %s\n", sp_buf);
		printf("netbios_port_list = %s\n", np_buf);
		printf("mac_exclusive (%d) netbios_exclusive (%d)\n", l->mac_exclusive, l->netbios_exclusive);
		for (i = 0; l->user_mac_addr_list[i] != NULL; i++) {
			printf("mac: %s ", pr_ether(l->user_mac_addr_list[i]->addr));
			printf("netmask: %s\n", pr_ether(l->user_mac_addr_list[i]->mask));
		}
	}

	printf("--------------ssp--------------\n");
	list_for_each(ent, &g->ssp_list) {
		s = list_entry(ent, struct dlsw_ssp_info, list);
		printf("version (%d) read (%d) write (%d) tcpconn (%d) window (%d)\n",
			s->version, s->read_port, s->write_port, s->tcpconn, s->window);
	}
	
        printf("------------partner------------\n");
	list_for_each(ent, &g->partner_list) {
		p = list_entry(ent, struct dlsw_partner_info, list);
		printf("ip (%s) version (%d) dir (%d) read (%d) write (%d)\n", inet_ntoa(p->ip),
			p->version, p->direction, p->read_port, p->write_port);
	}

pr_done:
        printf("=========================================================\n");
        return (0);
}

static global *parse_global(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	global *gi;
	if (!new(gi))
		return NULL;
	list_init_head(&gi->ssp_list);
	list_init_head(&gi->listen_list);
	list_init_head(&gi->partner_list);

	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if ((!strcmp(cur->name, "debuglevel")) && (cur->ns == ns))
                        gi->debug_level = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
	}
	return gi;
}

/* take a comma seperated sap list and return a NULL terminated array of saps. */
static u_int8_t **make_array_sap(char *saps)
{
	u_int8_t **sap_list;
	char *start, *high, *low;
	int i = 0;

	if (strlen(saps) <= 0)
		return NULL;
	start = new_s(strlen(saps));
	strcpy(start, saps);

	sap_list = new_s(400);
	
	start = strtok(start, ",");
	do {
		if (!strncmp(start, " ", 1))
			start++;
		sap_list[i] = new_s(sizeof(u_int8_t));
		sap_list[i] = (u_int8_t *)strtol(start, (char **)NULL, 0);
		i++;
	} while ((start = strtok(NULL, ",")) != NULL);
        return sap_list;
}

static u_int8_t **parse_sap_list(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	static u_int8_t **sap_list;

	sap_list = new_s(sizeof(u_int8_t) * 1);
	sap_list[0] = NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
                if ((!strcmp(cur->name, "sap")) && (cur->ns == ns)) {
			sap_list = make_array_sap(xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
		}
	}
	return sap_list;
}

static int in_ether_mask(char *bufp, unsigned char *ptr)
{
	u_int8_t c;

	c = atoi(bufp);
	memset(ptr, 0, ETH_ALEN);
	switch (c) {
		case 8:
			ptr[0] = 0xff;
			break;
		case 16:
			ptr[0] = ptr[1] = 0xff;
			break;
		case 24:
			ptr[0] = ptr[1] = ptr[2] = 0xff;
			break;
		case 32:
			ptr[0] = ptr[1] = ptr[2] = ptr[3] = 0xff;
			break;
		case 40:
			ptr[0] = ptr[1] = ptr[2] = ptr[3] = ptr[4] = 0xff;
			break;
		case 48:
			ptr[0] = ptr[1] = ptr[2] = ptr[3] = ptr[4] = ptr[5] = 0xff;
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

static int in_ether(char *bufp, unsigned char *ptr)
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
                        return -1;
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
                        return -1;
                }
                if(c != 0)
                        bufp++;
                *ptr++ = (unsigned char)(val & 0377);
                i++;

                /* We might get a semicolon here - not required. */
                if(*bufp == ':')
			bufp++;
	}
	return 0;
}

static int parse_mac_addr(struct dlsw_listen_info *l, char *mac, char *mask)
{
	int i, err;
	
	for (i = 0; l->user_mac_addr_list[i] != NULL; i++);
	l->user_mac_addr_list[i] = new_s(sizeof(dlsw_mac_addr_t));
	err = in_ether(mac, l->user_mac_addr_list[i]->addr);
	if (err < 0)
		return err;
	err = in_ether_mask(mask, l->user_mac_addr_list[i]->mask);
	if (err < 0)
		return err;
	return 0;
}

static struct dlsw_listen_info *parse_listen(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
        struct dlsw_listen_info *l;
        if (!new(l))
                return NULL;
	l->sna_sap_list = new_s(sizeof(u_int8_t));
	if (!l->sna_sap_list) {
		free(l);
		return NULL;
	}
	l->sna_sap_list[0] = NULL;
	l->netbios_sap_list = new_s(sizeof(u_int8_t));
	if (!l->netbios_sap_list) {
		free(l->sna_sap_list);
		free(l);
		return NULL;
	}
	l->netbios_sap_list[0] = NULL;
	l->user_mac_addr_list = new_s(sizeof(dlsw_mac_addr_t));
	if (!l->user_mac_addr_list) {
		free(l->sna_sap_list);
		free(l->netbios_sap_list);
		free(l);
		return NULL;
	}
	l->user_mac_addr_list[0] = NULL;
	l->user_netbios_name_list = new_s(sizeof(dlsw_netbios_name_t));
	if (!l->user_netbios_name_list) {
		free(l->sna_sap_list);
                free(l->netbios_sap_list);
		free(l->user_mac_addr_list);
		free(l);
		return NULL;
	}
	l->user_netbios_name_list[0] = NULL;
        for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
                if ((!strcmp(cur->name, "iface")) && (cur->ns == ns))
                        strcpy(l->ifname, xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "sna")) && (cur->ns == ns)) {
			l->sna_sap_list = parse_sap_list(doc, ns, cur);
			l->sna = 1;
                }
		if ((!strcmp(cur->name, "netbios")) && (cur->ns == ns)) {
			l->netbios_sap_list = parse_sap_list(doc, ns, cur);
			l->netbios = 1;
		}
		if ((!strcmp(cur->name, "mac_exclusive")) && (cur->ns == ns)) 
			l->mac_exclusive = map_word(yes_types, xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "netbios_exclusive")) && (cur->ns == ns))
			l->netbios_exclusive = map_word(yes_types,
				xmlNodeListGetString(doc, cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "mac")) && (cur->ns == ns)) {
			char *mm = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			char *mac, *mask;
			mac = strtok(mm, "/");
                        mask = strtok(NULL, "/");
                        if (mac == NULL) {
				printf("%s: invalid mac address, skipping\n", name_s);
				continue;
			}
			if (mask == NULL) {
		 		printf("%s: no mask or invalid mask, using /48\n", name_s);
				mask = new_s(3);
				strcpy(mask, "48");
			}		
			parse_mac_addr(l, mac, mask);
		}
        }
        return l;
}

static struct dlsw_partner_info *parse_partner(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	struct dlsw_partner_info *p;

	if (!new(p))
		return NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
                if ((!strcmp(cur->name, "ip")) && (cur->ns == ns)) {
			struct hostent *host = NULL;
			char *hostname;
			hostname = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			host = gethostbyname(hostname);
			if (!host) {
				printf("%s: unable to resolve hostname `%s'; partner is unavailable.",
					name_s, hostname);
				free(p);
				p = NULL;
				return p;
			}
			memcpy(&p->ip.s_addr, host->h_addr, host->h_length);
		}
		if ((!strcmp(cur->name, "version")) && (cur->ns == ns))
			p->version = atoi(xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "direction")) && (cur->ns == ns))
			p->direction = map_word(dir_types, xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
                if ((!strcmp(cur->name, "read")) && (cur->ns == ns))
                        p->read_port = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "write")) && (cur->ns == ns))
			p->write_port = atoi(xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
        }
	return p;
}

static struct dlsw_ssp_info *parse_ssp(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	struct dlsw_ssp_info *s;

	if (!new(s))
		return NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if ((!strcmp(cur->name, "version")) && (cur->ns == ns))
                        s->version = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
                if ((!strcmp(cur->name, "read")) && (cur->ns == ns))
                        s->read_port = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
                if ((!strcmp(cur->name, "write")) && (cur->ns == ns))
                        s->write_port = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "tcpconn")) && (cur->ns == ns))
			s->tcpconn = atoi(xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "window")) && (cur->ns == ns))
			s->window = atoi(xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
	}
	return s;
}

/* entrance for loading the standard dlswd.xml file. */
int load_config_file(char *cfile)
{
	xmlDocPtr doc;
        xmlNsPtr ns;
        xmlNodePtr cur;

        /* COMPAT: Do not genrate nodes for formatting spaces */
        LIBXML_TEST_VERSION
        xmlKeepBlanksDefault(0);

        /* build an XML tree from the file. */
        doc = xmlParseFile(cfile);
        if (!doc)
                return -1;

	/* check the document is of the right kind. */
        cur = xmlDocGetRootElement(doc);
        if (!cur) {
                fprintf(stderr, "file (%s) is an empty document.\n", cfile);
                xmlFreeDoc(doc);
                return -1;
        }
        ns = xmlSearchNsByHref(doc, cur, _PATH_DLSWD_XML_HREF);
        if (!ns) {
                fprintf(stderr, "file (%s) is of the wrong type,"
                        " dlswd namespace not found.\n", cfile);
                xmlFreeDoc(doc);
                return -1;
        }
	if (strcmp(cur->name, "Helping")) {
                fprintf(stderr, "file (%s) is of the wrong type,"
                        " root node != Helping.\n", cfile);
                xmlFreeDoc(doc);
                return -1;
        }

	/* now we walk the xml tree. */
        cur = cur->xmlChildrenNode;
        while (cur && xmlIsBlankNode(cur))
                cur = cur->next;
        if (!cur)
                return -1;

	/* first level is just 'dlswd' */
        if ((strcmp(cur->name, "dlswd")) || (cur->ns != ns)) {
                fprintf(stderr, "file (%s) is of the wrong type, was '%s',"
                        " dlswd expected", cfile, cur->name);
                fprintf(stderr, "xmlDocDump follows.\n");
                xmlDocDump(stderr, doc);
                fprintf(stderr, "xmlDocDump finished.\n");
                xmlFreeDoc(doc);
                return -1;
        }

	/* now we walk the xml tree. */
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if ((!strcmp(cur->name, "global")) && (cur->ns == ns)) {
			ginfo = parse_global(doc, ns, cur);
			if (!ginfo)
				return -EINVAL;
			continue;
		}
		if ((!strcmp(cur->name, "ssp")) && (cur->ns == ns)) {
			struct dlsw_ssp_info *s;
			s = parse_ssp(doc, ns, cur);
			if (!s)
				continue;
			list_add_tail(&s->list, &ginfo->ssp_list);
			continue;
		}
		if ((!strcmp(cur->name, "listen")) && (cur->ns == ns)) {
                        struct dlsw_listen_info *l;
                        l = parse_listen(doc, ns, cur);
                        if (!l)
                                continue;
			list_add_tail(&l->list, &ginfo->listen_list);
                        continue;
                }
		if ((!strcmp(cur->name, "partner")) && (cur->ns == ns)) {
			struct dlsw_partner_info *p;
			p = parse_partner(doc, ns, cur);
			if (!p)
				continue;
			list_add_tail(&p->list, &ginfo->partner_list);
			continue;
		}
	}

	dlsw_config_info = ginfo;
        return 0;
}

/* Now we actually do something with all the data we have gathered. */
int load_config(global *ginfo)
{
	struct list_head *ent;
	struct dlsw_listen_info *listen;
	struct dlsw_partner_info *partner;
	struct dlsw_ssp_info *ssp;
        int err = 0;

        if (dlsw_stats->debug > 5)
                dlsw_print_global(ginfo);
        if (!ginfo)
                return -ENOENT;
        if (ginfo->debug_level)
                dlsw_stats->debug = ginfo->debug_level;
	dlsw_load_user_table();
	list_for_each(ent, &ginfo->listen_list) {
		listen = list_entry(ent, struct dlsw_listen_info, list);
		err = dlsw_load_listen(listen);
		if (err < 0)
			return err;
	}
	list_for_each(ent, &ginfo->ssp_list) {
		ssp = list_entry(ent, struct dlsw_ssp_info, list);
                err = dlsw_load_local_ssp(ssp);
                if (err < 0)
                        return err;
        }
	list_for_each(ent, &ginfo->partner_list) {
		partner = list_entry(ent, struct dlsw_partner_info, list);
		err = dlsw_load_partner(partner);
		if (err < 0)
			return err;
	}
        return err;
}
