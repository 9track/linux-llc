#include <stdlib.h>
#include <string.h>   /* for NULL */
#include "parse.h"
#include "commands.h"

const char quithelp[] 		= "terminate sessions and exit";
const char helphelp[] 		= "print local help information";
const char networkhelp[] 	= "display network information";
const char suspendhelp[]	= "suspend all NPC communications, still allows plugin event processing";
const char resumehelp[]		= "resume NPC communcations";
const char debughelp[]		= "set debug level";
const char statushelp[] 	=  "show current status of netbotd";
const char systemhelp[] 	=  "show remote system information";
const char disconhelp[]		= "disconnect from server";
const char connecthelp[]	= "connect to server";

struct cmd cmdtab[] = {
	{ "bye",	quithelp,	0, 0, 0, NULL, quit, NULL },
	{ "close",	disconhelp,	0, 1, 1, NULL, disconnect, NULL },
	{ "debug",	debughelp,	0, 0, 1, setdebug, NULL, NULL },
	{ "disconnect",	disconhelp,	0, 1, 1, NULL, disconnect, NULL },
	{ "exit",	quithelp,	0, 0, 0, NULL, quit, NULL },
	{ "help",	helphelp,	0, 0, 1, help, NULL, NULL },
	{ "network",	networkhelp,	0, 1, 1, NULL, network, NULL },
	{ "open",	connecthelp,	0, 0, 1, open_monitor, NULL, NULL },
	{ "quit",	quithelp,	0, 0, 0, NULL, quit, NULL },
	{ "resume",	resumehelp,	0, 1, 1, NULL, resume, NULL },
	{ "status",	statushelp,	0, 1, 1, NULL, status, NULL },
	{ "suspend",	suspendhelp,	0, 1, 1, NULL, suspend, NULL },
	{ "system",	systemhelp,	0, 1, 1, NULL, syst, NULL },
	{ "?",		helphelp,	0, 0, 1, help, NULL, NULL },
	{ 0, 0, 0, 0, 0, 0, 0, 0 },
};

int	NCMDS = (sizeof (cmdtab) / sizeof (cmdtab[0])) - 1;
