/* llcdb.c: generic functions to get host <-> mac mapping.
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
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* required for llc sockets. */
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/llc.h>

#include <gnome-xml/xmlmemory.h>
#include <gnome-xml/parser.h>

/* out stuff. */
#include "llcdb.h"

static struct llcdbhost *allhosts = NULL;

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
                *ptr++ = (unsigned char)(val & 0377);
                i++;

                /* We might get a semicolon here - not required. */
                if(*bufp == ':')
                        bufp++;
        }

        return (0);
}

static struct llcdbhost *parse_host(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	struct llcdbhost *lh;
	lh = calloc(1, sizeof(*lh));
	if(!lh)
                return (NULL);

        for(cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
                if((!strcmp(cur->name, "name")) && (cur->ns == ns)) {
			char *tn = xmlNodeListGetString(doc,
				cur->xmlChildrenNode, 1);
			lh->host.lh_name = malloc(strlen(tn));
			strcpy(lh->host.lh_name, tn);
		}
		if((!strcmp(cur->name, "mac")) && (cur->ns == ns)) {
			lh->host.lh_addr = malloc(IFHWADDRLEN);
			in_ether(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1), lh->host.lh_addr);
			lh->host.lh_addrtype 	= ARPHRD_ETHER;
			lh->host.lh_length 	= IFHWADDRLEN;
		}
        }

        return (lh);
}

static int load_llchosts_file(char *cfile)
{
	struct llcdbhost *host;
	xmlDocPtr doc;
        xmlNsPtr ns;
        xmlNodePtr cur;

        /* COMPAT: Do not genrate nodes for formatting spaces */
        LIBXML_TEST_VERSION
        xmlKeepBlanksDefault(0);

        /* build an XML tree from the file. */
        doc = xmlParseFile(cfile);
        if(!doc)
                return (-1);

        /* check the document is of the right kind. */
        cur = xmlDocGetRootElement(doc);
        if(!cur) {
                fprintf(stderr, "file (%s) is an empty document.\n", cfile);
                xmlFreeDoc(doc);
                return (-1);
        }
        ns = xmlSearchNsByHref(doc, cur, _PATH_LLCHOSTS_XML_HREF);
        if(!ns) {
                fprintf(stderr, "file (%s) is of the wrong type,"
                        " llchosts namespace not found.\n", cfile);
                xmlFreeDoc(doc);
                return (-1);
        }
        if(strcmp(cur->name, "Helping")) {
                fprintf(stderr, "file (%s) is of the wrong type,"
                        " root node != Helping.\n", cfile);
                xmlFreeDoc(doc);
                return (-1);
        }

        /* now we walk the xml tree. */
        cur = cur->xmlChildrenNode;
        while(cur && xmlIsBlankNode(cur))
                cur = cur->next;
        if(!cur)
                return (-1);

        /* first level is just 'hosts' */
        if((strcmp(cur->name, "hosts")) || (cur->ns != ns)) {
                fprintf(stderr, "file (%s) is of the wrong type, was '%s',"
                        " hosts expected", cfile, cur->name);
                fprintf(stderr, "xmlDocDump follows.\n");
                xmlDocDump(stderr, doc);
                fprintf(stderr, "xmlDocDump finished.\n");
                xmlFreeDoc(doc);
                return (-1);
        }

        /* now we walk the xml tree. */
        for(cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next) {
                if((!strcmp(cur->name, "host")) && (cur->ns == ns)) {
                        host = parse_host(doc, ns, cur);
                        if(!host)
                                return (-EINVAL);
			host->next 	= allhosts;
			allhosts	= host;
                        continue;
                }
        }

        return (0);
}

static struct llchostent *find_llchost_by_name(const char *name, int *err)
{
	struct llcdbhost *ent;

	*err = 0;
	for(ent = allhosts; ent != NULL; ent = ent->next) {
		if(!strcmp(name, ent->host.lh_name))
			return (&ent->host);
	}

	*err = -ENOENT;
	return (NULL);
}

static struct llchostent *find_llchost_by_addr(const void *addr, 
	socklen_t len, int type, int *err)
{
	struct llcdbhost *ent;

	*err = 0;
        for(ent = allhosts; ent != NULL; ent = ent->next) {
		if(len == ent->host.lh_length
			&& type == ent->host.lh_addrtype
			&& !memcmp(addr, ent->host.lh_addr, len))
                        return (&ent->host);
        }

	*err = -ENOENT;
        return (NULL);
}

struct llchostent *getllchostbyname(const char *name)
{
	struct llchostent *host = NULL;
	int err = 0;

	err = load_llchosts_file(_PATH_LLCHOSTS);
	if(err < 0)
		goto done;
	host = find_llchost_by_name(name, &err);

done:	errno = err;
	return (host);
}

struct llchostent *getllchostbyaddr(const void *addr, socklen_t len, int type)
{
	struct llchostent *host = NULL;
        int err = 0;

        err = load_llchosts_file(_PATH_LLCHOSTS);
        if(err < 0)
                goto done;
	host = find_llchost_by_addr(addr, len, type, &err);

done:   errno = err;
	return (host);
}
