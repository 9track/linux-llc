#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <pwd.h>

#include "parse.h"

extern struct cmd cmdtab[];
extern int NCMDS;
extern char line[200];

char     *altarg;
char     *stringbase;
char     argbuf[200];    /* argument storage buffer */
char     *argbase;
int slrflag;

struct cmd *getcmd(const char *name)
{
        const char *p, *q;
        struct cmd *c, *found;
        int nmatches, longest;

        longest = 0;
        nmatches = 0;
        found = 0;
        for (c = cmdtab; (p = c->c_name) != NULL; c++) {
                for (q = name; *q == *p++; q++)
                        if (*q == 0)            /* exact match? */
                                return (c);
                if (!*q) {                      /* the name was a prefix */
                        if (q - name > longest) {
                                longest = q - name;
                                nmatches = 1;
                                found = c;
                        } else if (q - name == longest)
                                nmatches++;
                }
        }
        if (nmatches > 1)
                return ((struct cmd *)-1);
        return (found);
}

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

char **nmakeargv(int *pargc, char **parg)
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

int another(int *pargc, char ***pargv, const char *prompt)
{
        int margc;
        char **margv;

        unsigned len = strlen(line);
        int ret;

        if (len >= sizeof(line) - 3) {
                printf("sorry, arguments too long\n");
		// intr(0);
        }
        printf("(%s) ", prompt);
        line[len++] = ' ';
//        if (fgets(&line[len], sizeof(line) - len, stdin) == NULL)
//                intr(0);
        len += strlen(&line[len]);
        if (len > 0 && line[len - 1] == '\n')
                line[len - 1] = '\0';
        margv = nmakeargv(&margc, NULL);
        ret = margc > *pargc;
        *pargc = margc;
        *pargv = margv;
        return ret;
}
