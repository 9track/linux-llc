/* lar_unix.h: Lan address resolution unix communications defintions.
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

#ifndef _LAR_UNIX_H
#define _LAR_UNIX_H

struct larmsg {
	u_int16_t len;          /* size of lar_unix_hdr + payload. */
	u_int16_t type;		/* operation to perform. */
};

struct larattr {
	u_int16_t lara_len;
	u_int16_t lara_type;
};

enum larattr_type_t {
	LARA_CORRELATOR = 1,
	LARA_RTCAP,
	LARA_MAC,
	LARA_LSAP,
	LARA_NETID,
	LARA_NAME,
	LARA_GROUP,
	LARA_SOLICIT,
	LARA_SNPA,
	LARA_MEMBER,
	LARA_ERR
};

/* message header macros.
 */
#define LARMSG_GOODSIZE		4096
#define LARMSG_ALIGNTO   	4
#define LARMSG_ALIGN(len)  	(((len) + LARMSG_ALIGNTO - 1) & ~(LARMSG_ALIGNTO - 1))
#define LARMSG_LENGTH(len) 	((len) + LARMSG_ALIGN(sizeof(struct larmsg)))
#define LARMSG_SPACE(len)  	LARMSG_ALIGN(LARMSG_LENGTH(len))
#define LARMSG_DATA(lh)    	((void*)(((char*)lh) + LARMSG_LENGTH(0)))
#define LARMSG_NEXT(lh, len) 	((len) -= LARMSG_ALIGN((lh)->len), \
	(struct larmsg *)(((char*)(lh)) + LARMSG_ALIGN((lh)->len)))
#define LARMSG_OK(lh, len) 	((len) > 0 && (lh)->len >= sizeof(struct larmsg) && \
	(lh)->len <= (len))
#define LARMSG_PAYLOAD(lh, llen) ((lh)->len - LARMSG_SPACE((llen)))
#define LARMSG_NDATA(lh)	((void*)(LARMSG_DATA(lh) + LARMSG_PAYLOAD(lh, 0)))

/* attribute macros.
 */
#define LARA_ALIGNTO     	4
#define LARA_ALIGN(len) 	(((len) + LARA_ALIGNTO - 1) & ~(LARA_ALIGNTO - 1))
#define LARA_OK(lara, len) 	((len) > 0 && (lara)->lara_len >= sizeof(struct larattr) && \
				(lara)->lara_len <= (len))
#define LARA_NEXT(lara,attrlen) ((attrlen) -= LARA_ALIGN((lara)->lara_len), \
                                (struct larattr*)(((char*)(lara)) \
				+ LARA_ALIGN((lara)->lara_len)))
#define LARA_LENGTH(len) 	(LARA_ALIGN(sizeof(struct larattr)) + (len))
#define LARA_SPACE(len)  	LARA_ALIGN(LARA_LENGTH(len))
#define LARA_DATA(lara)   	((void*)(((char*)(lara)) + LARA_LENGTH(0)))
#define LARA_PAYLOAD(lara) 	((int)((lara)->lara_len) - LARA_LENGTH(0))

extern struct larmsg *larmsg_put(int type, int len);
extern struct larmsg *lara_put(struct larmsg *lh, int attrtype, int attrlen, 
	const void *attrdata);

extern int lar_unix_cnt_member(struct larattr *la, void *data, int *cnt);
extern int lar_unix_cnt_snpa(struct larattr *la, void *data, int *cnt);

extern int lar_unix_xtract_errno(struct larattr *la, void *data, int *err);
extern int lar_unix_xtract_member(struct larattr *la, void *data, 
        lar_member_t **members, int *cnt);
extern int lar_unix_xtract_snpa(struct larattr *la, void *data, 
	lar_snpa_t **snpa, int *cnt);

extern int lar_unix_rx_find(struct larattr *la, void *data, 
	lar_find_usr_t *find);
extern int lar_unix_rx_search(struct larattr *la, void *data, 
	lar_search_usr_t *srch);
extern int lar_unix_rx_record(struct larattr *la, void *data, 
	lar_record_usr_t *recd);
extern int lar_unix_rx_erase(struct larattr *la, void *data,
	lar_erase_usr_t *erase);

#define lar_attr_parse(lh, pfn, args...)                	\
({                                                      	\
        struct larattr *__la = LARMSG_DATA(lh);         	\
        int __llen = LARMSG_PAYLOAD(lh, 0);             	\
        int __err = 0;                                  	\
                                                        	\
        while (LARA_OK(__la, __llen)) {                 	\
                __err = pfn(__la, LARA_DATA(__la), ## args);    \
                if(__err != 0)                          	\
                        break;                          	\
                __la = LARA_NEXT(__la, __llen);         	\
        }                                               	\
        __err;                                          	\
})

extern int lar_unix_init(void);
extern int lar_unix_fini(int sk);
extern int lar_unix_send_errno(int skfd, int32_t err);
extern int lar_unix_send(int skfd, void *data, int len);
extern int lar_unix_recv(int skfd, void *data, int len);

#endif	/* _LAR_UNIX_H */
