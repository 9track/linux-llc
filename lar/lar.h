/* lar.h: Lan address resolution protocol defintions.
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

#define LAR_MAX_SV_GROUP_NAMES		20
#define LAR_MAX_SV_NETID_LEN		8
#define LAR_MAX_SV_NAME_LEN		8
#define LAR_MAX_SV_GROUP_LEN		8
#define LAR_MAX_SV_MAC_LEN		8
#define LAR_MAX_SV_CONN_NETID_LEN	17

typedef struct {
	u_int8_t 	len;
	u_int8_t 	id;
} sub_vector_t;

typedef struct {
	u_int16_t 	len;
	u_int8_t  	id;
} major_vector_t;

typedef u_int32_t	lar_correlator_t;
typedef u_int32_t	lar_rtcap_t;
typedef u_int8_t	lar_mac_t[LAR_MAX_SV_MAC_LEN];
typedef u_int8_t	lar_lsap_t;
typedef u_int8_t	lar_netid_t[LAR_MAX_SV_NETID_LEN];
typedef u_int8_t	lar_name_t[LAR_MAX_SV_NAME_LEN];
typedef u_int8_t	lar_group_t[LAR_MAX_SV_GROUP_LEN];
typedef u_int8_t	lar_conn_netid_t[LAR_MAX_SV_CONN_NETID_LEN];

typedef struct {
        lar_netid_t 		netid;
        lar_group_t 		group;
} lar_solicit_t;

typedef struct {
        lar_netid_t		netid;
        lar_name_t      	name;
        lar_lsap_t      	lsap;
        lar_mac_t       	mac;
        lar_rtcap_t     	rtcap;
	lar_conn_netid_t	conn_netid;
        lar_group_t     	*groups[LAR_MAX_SV_GROUP_NAMES];
        lar_mac_t       	cce_mac;
} lar_advertise_t;

typedef struct {
        lar_correlator_t 	correlator;
        lar_netid_t		tnetid;
        lar_name_t      	tname;
        lar_netid_t     	onetid;
        lar_name_t      	oname;
        lar_lsap_t      	olsap;
        lar_mac_t       	omac;
        lar_mac_t       	cce_mac;
} lar_find_t;

typedef struct {
        lar_correlator_t 	correlator;
        lar_lsap_t		lsap;
        lar_mac_t       	mac;
} lar_found_t;

typedef struct {
        lar_correlator_t 	correlator;
        lar_netid_t		netid;
	lar_group_t		group;
        lar_rtcap_t     	rtcap;
        lar_mac_t       	cce_mac;
} lar_query_t;

typedef struct {
        lar_correlator_t 	correlator;
        lar_lsap_t      	lsap;
        lar_mac_t       	mac;
        lar_netid_t     	netid;
        lar_name_t      	name;
        lar_group_t     	*groups[LAR_MAX_SV_GROUP_NAMES];
        lar_rtcap_t     	rtcap;
        lar_mac_t       	cce_mac;
} lar_notify_t;

typedef struct {
	lar_mac_t 		mac;
	lar_lsap_t 		lsap;
} lar_snpa_t;

typedef struct {
	lar_name_t		name;
	lar_snpa_t		snpa;
} lar_member_t;

typedef struct {
	lar_netid_t 		netid;
	lar_group_t 		group;
	lar_member_t		**members;
	lar_mac_t		cce_mac;
	lar_rtcap_t 		rtcap;
} lar_search_t;

/* major vector macros.
 */
#define LAR_MV_LENGTH(len)      ((len) + sizeof(major_vector_t))
#define LAR_MV_DATA(mv)		((void*)(((char*)mv) + LAR_MV_LENGTH(0)))
#define LAR_MV_SPACE(len)       LAR_MV_LENGTH(len)
#define LAR_MV_PAYLOAD(mv,llen) ((mv)->len - LAR_MV_SPACE((llen)))

/* sub vector macros.
 */
#define LAR_SV_OK(sv, llen)     ((llen) > 0 && (sv)->len >= sizeof(sub_vector_t) && \
                                (sv)->len <= (llen))
#define LAR_SV_NEXT(sv,attrlen) ((attrlen) -= (sv)->len, \
				(sub_vector_t *)(((char *)(sv)) + (sv)->len))
#define LAR_SV_LENGTH(len)      (sizeof(sub_vector_t) + (len))
#define LAR_SV_SPACE(len)	LAR_SV_LENGTH(len)
#define LAR_SV_DATA(sv)         ((void*)(((char*)(sv)) + LAR_SV_LENGTH(0)))
#define LAR_SV_PAYLOAD(sv)	((int)((sv)->len) - LAR_SV_LENGTH(0))

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

extern int lar_find_member(const u_int8_t fflag, const u_int8_t *netid,
        const u_int8_t *group, const u_int32_t rtmask, lar_search_t *member);
extern int lar_find(const u_int8_t *netid, const u_int8_t *name, lar_snpa_t *snpa);
extern int lar_search(const u_int8_t *netid, const u_int8_t *group,
        const u_int32_t rtcap, lar_member_t *members);
extern int lar_record(const u_int8_t *netid, const u_int8_t *name,
        const u_int32_t rtcap, lar_snpa_t **snpa_list,
        u_int8_t **groups);
extern int lar_erase(const u_int8_t *netid, const u_int8_t *name);
#endif	/* _LAR_H */
