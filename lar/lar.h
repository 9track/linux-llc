/* lar.h: Lan address resolution protocol defintions.
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

#ifndef _LAR_H
#define _LAR_H

enum lar_mv_type {
	LAR_MV_SOLICIT = 0x01,
	LAR_MV_ADVERTISE,
	LAR_MV_FIND,
	LAR_MV_FOUND,
	LAR_MV_QUERY,
	LAR_MV_NOTIFY,
	LAR_MV_MAX
};

enum lar_sv_type {
	LAR_SV_GROUP_NAME = 0x00,
	LAR_SV_RESOURCE_NAME,
	LAR_SV_RTCAP,
	LAR_SV_CONN_NETID,
	LAR_SV_RETURN_CCE_MAC,
	LAR_SV_CORRELATOR,
	LAR_SV_TARGET_NAME,
	LAR_SV_ORIGIN_NAME,
	LAR_SV_ORIGIN_LSAP,
	LAR_SV_ORIGIN_MAC,
	LAR_SV_ORIGIN_CCE_MAC,
	LAR_SV_RESOURCE_LSAP,
	LAR_SV_RESOURCE_MAC,
	LAR_SV_TARGET_NETID,
	LAR_SV_RESOURCE_NETID,
	LAR_SV_GROUP_NAMES = 0x81
};
#define LAR_SV_ORIGIN_NETID	LAR_SV_RESOURCE_NETID

enum lar_group_name {
	LAR_GN_USER = 0,
	LAR_GN_IGO2HOST,
	LAR_GN_IROUTSNA,
	LAR_GN_IGIVNAME,
	LAR_GN_MAX
};

#define LAR_RTCAP_SUBAREA       	0x40
#define LAR_RTCAP_APPN_NN       	0x80
#define LAR_RTCAP_NAME          	0xAA

#define LAR_MAX_I_LEN			480
#define LAR_MAX_SV_GROUP_NAMES		20
#define LAR_MAX_SV_NETID_LEN		8
#define LAR_MAX_SV_NAME_LEN		8
#define LAR_MAX_SV_GROUP_LEN		8
#define LAR_MAX_SV_MAC_LEN		6
#define LAR_MAX_SV_CONN_NETID_LEN	17

#ifndef LLC_SAP_LAR
#define LLC_SAP_LAR			0xDC
#endif

typedef struct {
	u_int8_t 	len;
	u_int8_t 	id;
} sub_vector_t;
#define LAR_SV_T_LEN	2

typedef struct {
	u_int16_t 	len;
	u_int8_t  	id;
} major_vector_t;
#define LAR_MV_T_LEN	3

typedef u_int32_t	lar_correlator_t;
typedef u_int32_t	lar_rtcap_t;
typedef u_int8_t	lar_mac_t[LAR_MAX_SV_MAC_LEN];
typedef u_int8_t	lar_lsap_t;
typedef u_int8_t	lar_netid_t[LAR_MAX_SV_NETID_LEN];
typedef u_int8_t	lar_name_t[LAR_MAX_SV_NAME_LEN];
typedef u_int8_t	lar_group_t[LAR_MAX_SV_GROUP_LEN];
typedef u_int8_t	lar_conn_netid_t[LAR_MAX_SV_CONN_NETID_LEN];
typedef u_int8_t	lar_len_t;

typedef struct {
        lar_netid_t 		netid;
	lar_len_t               netid_len;
        lar_group_t 		group;
	lar_len_t               group_len;
} lar_solicit_pkt_t;

typedef struct {
        lar_netid_t		netid;
	lar_len_t		netid_len;
        lar_name_t      	name;
	lar_len_t		name_len;
        lar_lsap_t      	lsap;
        lar_mac_t       	mac;
        lar_rtcap_t     	rtcap;
	lar_conn_netid_t	conn_netid;
	lar_len_t		conn_netid_len;
        lar_group_t     	**groups;
        lar_mac_t       	cce_mac;
} lar_advertise_pkt_t;

typedef struct {
        lar_correlator_t        correlator;
        lar_netid_t             tnetid;
	lar_len_t		tnetid_len;
        lar_name_t              tname;
	lar_len_t		tname_len;
        lar_netid_t             onetid;
	lar_len_t		onetid_len;
        lar_name_t              oname;
	lar_len_t		oname_len;
        lar_lsap_t              olsap;
        lar_mac_t               omac;
        lar_mac_t               cce_mac;
} lar_find_pkt_t;

typedef struct {
        lar_correlator_t 	correlator;
        lar_lsap_t		lsap;
        lar_mac_t       	mac;
} lar_found_pkt_t;

typedef struct {
        lar_correlator_t        correlator;
        lar_netid_t             netid;
	lar_len_t		netid_len;
        lar_group_t             group;
	lar_len_t		group_len;
        lar_rtcap_t             rtcap;
        lar_mac_t               cce_mac;
} lar_query_pkt_t;

typedef struct {
        lar_correlator_t 	correlator;
        lar_lsap_t      	lsap;
        lar_mac_t       	mac;
        lar_netid_t     	netid;
	lar_len_t		netid_len;
        lar_name_t      	name;
	lar_len_t		name_len;
        lar_group_t     	*groups[LAR_MAX_SV_GROUP_NAMES];
        lar_rtcap_t     	rtcap;
        lar_mac_t       	cce_mac;
} lar_notify_pkt_t;

typedef struct {
	lar_mac_t 		mac;
	lar_lsap_t 		lsap;
} lar_snpa_t;

typedef struct {
	lar_name_t		name;
	lar_snpa_t		snpa;
} lar_member_t;

typedef struct {
	lar_name_t		name;
	lar_netid_t		netid;
	lar_rtcap_t		rtcap;
	lar_group_t		*groups[LAR_MAX_SV_GROUP_NAMES];
	lar_snpa_t		*snpas[LAR_MAX_SV_GROUP_NAMES];
} lar_record_usr_t;

typedef struct {
	lar_name_t		name;
	lar_netid_t		netid;
} lar_erase_usr_t;

typedef struct {
        lar_name_t              name;
        lar_netid_t             netid;
} lar_find_usr_t;

typedef struct {
	lar_netid_t 		netid;
	lar_group_t 		group;
	lar_member_t		**members;
	lar_mac_t		cce_mac;
	lar_rtcap_t 		rtcap;
} lar_search_usr_t;

/* user functions.
 */
enum lar_op_type {
	LAR_OP_ERRNO = 0,
	LAR_OP_ERASE,
	LAR_OP_RECORD,
	LAR_OP_FIND,
	LAR_OP_FIND_MEMBER,
	LAR_OP_SEARCH
};

extern int32_t lar_erase(const u_int8_t *netid, const u_int8_t *name);
extern int32_t lar_record(const u_int8_t *netid, const u_int8_t *name,
        const u_int32_t rtcap, lar_snpa_t **snpa_list, u_int8_t **groups);
extern lar_snpa_t **lar_find(const u_int8_t *netid, const u_int8_t *name, 
        int32_t *rc);
extern lar_member_t **lar_find_member(const u_int8_t fflag,
        const u_int8_t *netid, const u_int8_t *group, const u_int32_t rtmask,
        int32_t *rc);
extern lar_member_t **lar_search(const u_int8_t *netid, const u_int8_t *group,
        const u_int32_t rtcap, int32_t *rc);

/* major vector macros.
 */
#define LAR_MV_LENGTH(len)      ((len) + LAR_MV_T_LEN)
#define LAR_MV_DATA(mv)		((void*)(((char*)mv) + LAR_MV_LENGTH(0)))
#define LAR_MV_SPACE(len)       LAR_MV_LENGTH(len)
#define LAR_MV_PAYLOAD(mv,llen) ((mv)->len - LAR_MV_SPACE((llen)))
#define LAR_MV_NEXTDATA(mv)	((void *)(LAR_MV_DATA(mv) + LAR_MV_PAYLOAD(mv, 0)))

#define lar_major_vector_put(mvid, mvlen)			\
({								\
	major_vector_t *__mv = calloc(1, mvlen);		\
	__mv->id	= mvid;					\
	__mv->len	= mvlen;				\
	__mv;							\
})

/* sub vector macros.
 */
#define LAR_SV_OK(sv, llen)     ((llen) > 0 && (sv)->len >= LAR_SV_T_LEN && \
                                (sv)->len <= (llen))
#define LAR_SV_NEXT(sv,attrlen) ((attrlen) -= (sv)->len, \
				(sub_vector_t *)(((char *)(sv)) + (sv)->len))
#define LAR_SV_LENGTH(len)      (LAR_SV_T_LEN + (len))
#define LAR_SV_SPACE(len)	LAR_SV_LENGTH(len)
#define LAR_SV_DATA(sv)         ((void*)(((char*)(sv)) + LAR_SV_LENGTH(0)))
#define LAR_SV_PAYLOAD(sv)	((int)((sv)->len) - LAR_SV_LENGTH(0))

#define lar_sub_vector_put(mv, svid, svlen, svdata)		\
({								\
	sub_vector_t *__sv;					\
	int __llen = LAR_SV_LENGTH(svlen);			\
								\
	mv = realloc(mv, mv->len + __llen);			\
	__sv = LAR_MV_NEXTDATA(mv);				\
	__sv->len = __llen;					\
	__sv->id  = svid;					\
	memcpy(LAR_SV_DATA(__sv), svdata, svlen);		\
	mv->len += __llen;					\
	mv;							\
})

#define lar_sub_vector_parse(mv, pfn, args...)                  \
({                                                              \
        sub_vector_t *__sv = LAR_MV_DATA(mv);                 	\
        int __llen = LAR_MV_PAYLOAD(mv, 0);                     \
        int __err = 0;                                          \
                                                                \
	while (LAR_SV_OK(__sv, __llen)) {                       \
		__err = pfn(__sv, LAR_SV_DATA(__sv), ## args);	\
                if(__err != 0)                                  \
                       break;                                   \
                __sv = LAR_SV_NEXT(__sv, __llen);               \
	}                                                       \
        __err;                                                  \
})

#define lar_ssub_vector_parse(sv, pfn, args...)			\
({                                                              \
        sub_vector_t *__ssv = LAR_SV_DATA(sv);                  \
        int __llen = LAR_SV_PAYLOAD(sv);                     	\
        int __err = 0;                                          \
                                                                \
        while (LAR_SV_OK(__ssv, __llen)) {                      \
                __err = pfn(__ssv, LAR_SV_DATA(__ssv), ## args);\
                if(__err != 0)                                  \
                       break;                                   \
                __ssv = LAR_SV_NEXT(__ssv, __llen);             \
        }                                                       \
        __err;                                                  \
})
#endif	/* _LAR_H */
