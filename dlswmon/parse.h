struct cmd {
        const char *c_name;     /* name of command */
        const char *c_help;     /* help string */
        char c_bell;            /* give bell when command completes */
        char c_conn;            /* must be connected to use command */
        char c_proxy;           /* proxy server may execute */

        /* Exactly one of these should be non-NULL. */
        void (*c_handler_v)(int, char **); /* function to call */
        void (*c_handler_0)(void);
        void (*c_handler_1)(const char *);
};

extern char **nmakeargv(int *pargc, char **parg);
extern struct cmd *getcmd(const char *name);
extern int another(int *pargc, char ***pargv, const char *prompt);
