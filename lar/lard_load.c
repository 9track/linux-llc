/* lard_load.c: load an lar server configuration file.
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
#include "lar.h"
#include "lar_list.h"
#include "lard_load.h"
#include "lard.h"

#include <gnome-xml/xmlmemory.h>
#include <gnome-xml/parser.h>

static global *ginfo = NULL;
extern global *lar_config_info;
extern struct lar_statistics *lar_stats;

struct wordmap on_types[] = {
        { "off",        0               },
        { "on",         1               },
        { NULL,         -1              }
};

static int map_word(struct wordmap *wm, const char *word)
{
        int i;
        for (i = 0; wm[i].word != NULL; i++)
                if (!strcmp(wm[i].word, word))
                        return wm[i].val;
        return -1;
}

int lard_print_global(global *g)
{
        struct lar_tinfo *t;
	struct lar_linfo *l;

        printf("\n================ Global Input Structure ================\n");

        if (!g) {
                printf("Global data is NULL!\n");
                goto pr_done;
        }

        printf("debug_level: %d\n", g->debug_level);
	printf("lsap: 0x%02X\n", g->lsap);
	printf("timetolive: %d\n", g->timetolive);

	printf("------------listen-------------\n");
	for (l = g->ll; l != NULL; l = l->next)
		printf("iface (%s) igivname (%d)\n",
			l->ifname, l->igivname);

        printf("-------------timer-------------\n");
        for (t = g->tl; t != NULL; t = t->next)
		printf("name (%s) secs (%d) count (%d)\n",
			t->name, t->secs, t->count);

pr_done:
        printf("=========================================================\n");
        return 0;
}

static struct lar_tinfo *parse_timer(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	struct lar_tinfo *t;
        if (!new(t))
                return NULL;
        for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
                if ((!strcmp(cur->name, "name")) && (cur->ns == ns))
			strncpy(t->name, xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1), 30);
		if ((!strcmp(cur->name, "secs")) && (cur->ns == ns))
			t->secs = atoi(xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "count")) && (cur->ns == ns))
			t->count = atoi(xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1));
	}
	return t;
}

static struct lar_linfo *parse_listen(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
        struct lar_linfo *l;
        if (!new(l))
                return NULL;
        for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if ((!strcmp(cur->name, "igivname")) && (cur->ns == ns))
                        l->igivname = map_word(on_types, xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "iface")) && (cur->ns == ns))
			strcpy(l->ifname, xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
	}
	return l;
}

static global *parse_global(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	global *gi;
	if (!new(gi))
		return NULL;
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
		if ((!strcmp(cur->name, "debuglevel")) && (cur->ns == ns))
                        gi->debug_level = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
		if ((!strcmp(cur->name, "lsap")) && (cur->ns == ns))
			gi->lsap = strtol(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1), (char **)NULL, 0);
		if ((!strcmp(cur->name, "timetolive")) && (cur->ns == ns))
                        gi->timetolive = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
	}
	return gi;
}

/* entrance for loading the standard lard.xml file. */
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
        ns = xmlSearchNsByHref(doc, cur, _PATH_LARD_XML_HREF);
        if (!ns) {
                fprintf(stderr, "file (%s) is of the wrong type,"
                        " lard namespace not found.\n", cfile);
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

	/* first level is just 'lard' */
        if ((strcmp(cur->name, "lard")) || (cur->ns != ns)) {
                fprintf(stderr, "file (%s) is of the wrong type, was '%s',"
                        " lard expected", cfile, cur->name);
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

		if ((!strcmp(cur->name, "listen")) && (cur->ns == ns)) {
			struct lar_linfo *l;
			l = parse_listen(doc, ns, cur);
			if (!l)
				continue;
			l->next = ginfo->ll;
			ginfo->ll = l;
			continue;
		}

		if ((!strcmp(cur->name, "timer")) && (cur->ns == ns)) {
			struct lar_tinfo *t;
			t = parse_timer(doc, ns, cur);
			if (!t)
				continue;
			t->next = ginfo->tl;
                        ginfo->tl = t;
			continue;
                }
	}

	lar_config_info = ginfo;
        return 0;
}

/* Now we actually do something with all the data we have gathered. */
int load_config(global *ginfo)
{
	struct lar_tinfo *t;
	struct lar_linfo *l;
        int err = 0;

        if (lar_stats->debug > 5)
                lard_print_global(ginfo);
        if (!ginfo)
                return -ENOENT;
	if (ginfo->debug_level)
                lar_stats->debug = ginfo->debug_level;
	lar_stats->garbage_ttl = ginfo->timetolive;
        for (t = ginfo->tl; t != NULL; t = t->next) {
                err = lar_load_timer(t);
		if (err < 0)
			return err;
	}
	err = lar_load_unix();
        if (err < 0)
                return err;
	for (l = ginfo->ll; l != NULL; l = l->next) {
		err = lar_load_listen(l);
		if (err < 0)
			return err;
	}
        return err;
}
