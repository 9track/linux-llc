/* dlsw_vector.h: Data link switching configuration  vector structures defintions.
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

#ifndef _DLSW_VECTOR_H
#define _DLSW_VECTOR_H

typedef struct {
	u_int8_t	len;
	u_int8_t	id;
} sub_vector_t;

typedef struct {
	u_int16_t	len;
	u_int16_t	id;
} major_vector_t;

enum dlsw_mv_type {
	DLSW_MV_CAP_XCHNG_CMD = 0x1520,
	DLSW_MV_CAP_XCHNG_POS_RSP,
	DLSW_MV_CAP_XCHNG_NEG_RSP
};
	
enum dlsw_sv_type {
	DLSW_SV_VENDOR_ID = 0x81,
	DLSW_SV_VERSION,
	DLSW_SV_INIT_PACE_WIN,
	DLSW_SV_VERSION_STRING,
	DLSW_SV_MAC_ADDR_EXCLSV,
	DLSW_SV_SAP_LIST,
	DLSW_SV_TCP_CONN,
	DLSW_SV_NETBIOS_NAME_EXCLSV,
	DLSW_SV_MAC_ADDR_LIST,
	DLSW_SV_NETBIOS_NAME_LIST,
	DLSW_SV_VENDOR_CONTEXT
};

enum dlsw_invalid_type {
        DLSW_INVALID_UNKNOWN = 0,
        DLSW_INVALID_GDS_LEN,
        DLSW_INVALID_GDS_ID,
        DLSW_INVALID_VENDOR_ID,
        DLSW_INVALID_VERSION,
        DLSW_INVALID_PACE_WIN,
        DLSW_INVALID_LEN,
        DLSW_INVALID_VECTOR_ID,
        DLSW_INVALID_VECTOR_LEN,
        DLSW_INVALID_VECTOR_DATA,
        DLSW_INVALID_DUP_VECTOR,
        DLSW_INVALID_OOS_VECTOR,
        DLSW_INVALID_SAP_LIST,
        DLSW_INVALID_MAX
};

typedef u_int8_t		dlsw_oui_t[3];
typedef u_int8_t		dlsw_vstring_t[40];
typedef u_int16_t		dlsw_pace_win_t;
typedef u_int8_t		dlsw_exclusive_t;
typedef u_int8_t		dlsw_sap_list_t[16];
typedef u_int8_t		dlsw_tcp_conn_t;
typedef u_int8_t        	dlsw_netbios_name_t[40];

typedef struct {
	u_int8_t		version;
	u_int8_t		release;
} dlsw_version_t;

typedef struct {
	u_int8_t		addr[6];
	u_int8_t		mask[6];
} dlsw_mac_addr_t;

typedef struct {
	u_int8_t		group;
	dlsw_netbios_name_t	**names;
} dlsw_netbios_names_t;

typedef struct {
        u_int16_t               offset;
        u_int16_t               reason;
} dlsw_cap_reason_t;

#define DLSW_CAP_VFIELD_VENDOR_ID		0x0001
#define DLSW_CAP_VFIELD_VERSION			0x0002
#define DLSW_CAP_VFIELD_PACE_WIN		0x0004
#define DLSW_CAP_VFIELD_VERSION_STRING		0x0008
#define DLSW_CAP_VFIELD_MAC_ADDR_EXCLSV		0x0010
#define DLSW_CAP_VFIELD_SAP_LIST		0x0020
#define DLSW_CAP_VFIELD_TCP_CONN		0x0040
#define DLSW_CAP_VFIELD_NETBIOS_NAME_EXCLSV	0x0080
#define DLSW_CAP_VFIELD_MAC_ADDR		0x0100
#define DLSW_CAP_VFIELD_NETBIOS_NAMES		0x0200
#define DLSW_CAP_VFIELD_VENDOR_CONTEXT		0x0400

typedef struct {
	u_int32_t 		vfield;
	dlsw_oui_t 		vendor_id;
	dlsw_version_t		version;
	dlsw_pace_win_t		pace_win;
	dlsw_vstring_t		version_string;
	dlsw_exclusive_t	mac_addr_exclsv;
	dlsw_sap_list_t		sap_list;
	dlsw_tcp_conn_t		tcp_conn;
	dlsw_exclusive_t	netbios_name_exclsv;
	dlsw_mac_addr_t		mac_addr;
	dlsw_netbios_names_t	netbios_names;
	dlsw_oui_t		vendor_context;
} dlsw_cap_cmd_pkt_t;

typedef struct {
	dlsw_cap_reason_t	*code[DLSW_INVALID_MAX];
} dlsw_cap_rsp_pkt_t;

/* major vector macros.
 */
#define DLSW_MV_LENGTH(len)      ((len) + sizeof(major_vector_t))
#define DLSW_MV_DATA(mv)         ((void*)(((char*)mv) + DLSW_MV_LENGTH(0)))
#define DLSW_MV_SPACE(len)       DLSW_MV_LENGTH(len)
#define DLSW_MV_PAYLOAD(mv,llen) ((mv)->len - DLSW_MV_SPACE((llen)))
#define DLSW_MV_NH_PAYLOAD(mv,llen) (ntohs((mv)->len) - DLSW_MV_SPACE((llen)))
#define DLSW_MV_NEXTDATA(mv)     ((void *)(DLSW_MV_DATA(mv) + DLSW_MV_PAYLOAD(mv, 0)))

#define dlsw_major_vector_put(mvid, mvlen)                      \
({                                                              \
        major_vector_t *__mv = calloc(1, mvlen);                \
        __mv->id        = mvid;                                 \
        __mv->len       = mvlen;                                \
        __mv;                                                   \
})

/* sub vector macros.
 */
#define DLSW_SV_OK(sv, llen)	((llen) > 0 && (sv)->len >= sizeof(sub_vector_t) && \
                                (sv)->len <= (llen))
#define DLSW_SV_NEXT(sv,attrlen) ((attrlen) -= (sv)->len, \
                                (sub_vector_t *)(((char *)(sv)) + (sv)->len))
#define DLSW_SV_LENGTH(len)     (sizeof(sub_vector_t) + (len))
#define DLSW_SV_SPACE(len)      DLSW_SV_LENGTH(len)
#define DLSW_SV_DATA(sv)        ((void*)(((char*)(sv)) + DLSW_SV_LENGTH(0)))
#define DLSW_SV_PAYLOAD(sv)     ((int)((sv)->len) - DLSW_SV_LENGTH(0))

#define dlsw_sub_vector_put(mv, svid, svlen, svdata)            \
({                                                              \
        sub_vector_t *__sv;                                     \
        int __llen = DLSW_SV_LENGTH(svlen);                     \
                                                                \
        mv = realloc(mv, mv->len + __llen);                     \
        __sv = DLSW_MV_NEXTDATA(mv);                            \
        __sv->len = __llen;                                     \
        __sv->id  = svid;                                       \
        memcpy(DLSW_SV_DATA(__sv), svdata, svlen);              \
        mv->len += __llen;                                      \
        mv;                                                     \
})

#define dlsw_sub_vector_parse(mv, pfn, args...)                 \
({                                                              \
        sub_vector_t *__sv = DLSW_MV_DATA(mv);                  \
        int __llen = DLSW_MV_NH_PAYLOAD(mv, 0);                 \
        int __err = 0;                                          \
                                                                \
        while (DLSW_SV_OK(__sv, __llen)) {                      \
                __err = pfn(__sv, DLSW_SV_DATA(__sv), ## args);	\
                if(__err != 0)                                  \
                       break;                                   \
                __sv = DLSW_SV_NEXT(__sv, __llen);              \
        }                                                       \
        __err;                                                  \
})

extern int dlsw_vect_rx_cap_xchng_c_print(sub_vector_t *sv, void *data);
extern int dlsw_vect_rx_cap_xchng_c(sub_vector_t *sv, void *data, 
	dlsw_cap_cmd_pkt_t *cap_c);
extern int dlsw_vect_rx_cap_xchng_r(major_vector_t *mv, void *data, 
	dlsw_cap_rsp_pkt_t *cap_r);

extern major_vector_t *dlsw_vect_tx_cap_xchng_c(dlsw_cap_cmd_pkt_t *cap_c);
extern major_vector_t *dlsw_vect_tx_cap_xchng_pos_r(void);
extern major_vector_t *dlsw_vect_tx_cap_xchng_neg_r(dlsw_cap_rsp_pkt_t *cap_r);

#endif	/* _DLSW_VECTOR_H */
