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
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <dlsw_load.h>
#include <dlswd.h>

#include <gnome-xml/xmlmemory.h>
#include <gnome-xml/parser.h>

static global *ginfo = NULL;
extern global *dlsw_config_info;
extern struct dlsw_statistics *dlsw_stats;

struct wordmap on_types[] = {
        { "off",        0               },
        { "on",         1               },
        { NULL,         -1              }
};

char     *altarg;
char     *stringbase;
char     argbuf[200];    /* argument storage buffer */
char     *argbase;
int slrflag;

char *slurpstring(void)
{
        static char excl[] = "!", dols[] = "$";

        int got_one = 0;
        register char *sb = stringbase;
        register char *ap = argbase;
        char *tmp = argbase;            /* will return this if token found */

        if (*sb == '!' || *sb == '$') { /* recognize ! as a token for shell */
                switch (slrflag) {      /* and $ as token for macro invoke */
                        case 0:
                                slrflag++;
                                stringbase++;
                                return ((*sb == '!') ? excl : dols);
                                /* NOTREACHED */
                        case 1:
                                slrflag++;
                                altarg = stringbase;
                                break;
                        default:
                                break;
                }
        }

S0:
        switch (*sb) {

        case '\0':
                goto OUT;

        case ' ':
        case '\t':
                sb++; goto S0;

        default:
                switch (slrflag) {
                        case 0:
                                slrflag++;
                                break;
                        case 1:
                                slrflag++;
                                altarg = sb;
                                break;
                        default:
                                break;
                }
                goto S1;
        }

S1:
        switch (*sb) {

        case ' ':
        case '\t':
        case '\0':
                goto OUT;       /* end of token */

        case '\\':
                sb++; goto S2;  /* slurp next character */

        case '"':
                sb++; goto S3;  /* slurp quoted string */

        default:
                *ap++ = *sb++;  /* add character to token */
                got_one = 1;
                goto S1;
        }

S2:
        switch (*sb) {

        case '\0':
                goto OUT;

        default:
                *ap++ = *sb++;
                got_one = 1;
                goto S1;
        }

S3:
        switch (*sb) {

        case '\0':
                goto OUT;

        case '"':
                sb++; goto S1;

        default:
                *ap++ = *sb++;
                got_one = 1;
                goto S3;
        }

OUT:
        if (got_one)
                *ap++ = '\0';
        argbase = ap;                   /* update storage pointer */
        stringbase = sb;                /* update scan pointer */
        if (got_one) {
                return(tmp);
        }
        switch (slrflag) {
                case 0:
                        slrflag++;
                        break;
                case 1:
                        slrflag++;
                        altarg = NULL;
                        break;
                default:
                        break;
        }
        return NULL;
}

char **makeargv(char *line, int *pargc, char **parg)
{
        static char *rargv[20];
        int rargc = 0;
        char **argp;

        argp = rargv;
        stringbase = line;              /* scan from first of buffer */
        argbase = argbuf;               /* store from first of buffer */
        slrflag = 0;
        while((*argp++ = slurpstring())!=NULL)
                rargc++;

        *pargc = rargc;
        if(parg)
                *parg = altarg;
        return (rargv);
}

int map_word(struct wordmap *wm, const char *word)
{
        int i;
        for(i = 0; wm[i].word != NULL; i++)
                if(!strcmp(wm[i].word, word))
                        return (wm[i].val);

        return (-1);
}

int dlsw_print_global(global *g)
{
        struct monitor *m;

        printf("\n================ Global Input Structure ================\n");

        if(!g)
        {
                printf("Global data is NULL!\n");
                goto pr_done;
        }

        printf("debug_level: %d\n", g->debug_level);

        printf("-------------Monitor-------------\n");
        for(m = g->m; m != NULL; m = m->next)
                printf("port: %d\n", m->port);

pr_done:
        printf("=========================================================\n");
        return (0);
}

static struct monitor *parse_monitor(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	struct monitor *m;
        if(!new(m))
                return (NULL);

        for(cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
        {
                if((!strcmp(cur->name, "port")) && (cur->ns == ns))
                        m->port = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
	}

	return (m);
}

static global *parse_global(xmlDocPtr doc, xmlNsPtr ns, xmlNodePtr cur)
{
	global *gi;
	if(!new(gi))
		return (NULL);

	for(cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
        {
		if((!strcmp(cur->name, "debuglevel")) && (cur->ns == ns))
                        gi->debug_level = atoi(xmlNodeListGetString(doc,
                                cur->xmlChildrenNode, 1));
	}

	return (gi);
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
        if(!doc)
                return (-1);

	/* check the document is of the right kind. */
        cur = xmlDocGetRootElement(doc);
        if(!cur)
        {
                fprintf(stderr, "file (%s) is an empty document.\n", cfile);
                xmlFreeDoc(doc);
                return (-1);
        }
        ns = xmlSearchNsByHref(doc, cur, _PATH_DLSWD_XML_HREF);
        if(!ns)
        {
                fprintf(stderr, "file (%s) is of the wrong type,"
                        " dlswd namespace not found.\n", cfile);
                xmlFreeDoc(doc);
                return (-1);
        }
	if(strcmp(cur->name, "Helping"))
        {
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

	/* first level is just 'dlswd' */
        if((strcmp(cur->name, "dlswd")) || (cur->ns != ns))
        {
                fprintf(stderr, "file (%s) is of the wrong type, was '%s',"
                        " dlswd expected", cfile, cur->name);
                fprintf(stderr, "xmlDocDump follows.\n");
                xmlDocDump(stderr, doc);
                fprintf(stderr, "xmlDocDump finished.\n");
                xmlFreeDoc(doc);
                return (-1);
        }

	/* now we walk the xml tree. */
	for(cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
        {
		if((!strcmp(cur->name, "global")) && (cur->ns == ns))
		{
			ginfo = parse_global(doc, ns, cur);
			if(!ginfo)
				return (-EINVAL);
			continue;
		}

		if((!strcmp(cur->name, "monitor")) && (cur->ns == ns))
                {
			struct monitor *m;
			m = parse_monitor(doc, ns, cur);
			if(!m)
				continue;
			m->next = ginfo->m;
                        ginfo->m = m;
			continue;
                }
	}

	dlsw_config_info = ginfo;
        return (0);
}

/* Now we actually do something with all the data we have gathered. */
int load_config(global *ginfo)
{
        struct monitor *m;
        int err = 0;

        if(dlsw_stats->debug > 5)
                dlsw_print_global(ginfo);

        if(!ginfo)
                return (-ENOENT);

        if(ginfo->debug_level)
                dlsw_stats->debug = ginfo->debug_level;

        for(m = ginfo->m; m != NULL; m = m->next)
                err = dlsw_load_monitor(m);

        return (err);
}
