/* dlsw_vector.c: configuration vector functions.
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

/* out stuff. */
#include <dlsw_vector.h>

int dlsw_vect_rx_cap_xchng_r(major_vector_t *mv, void *data, dlsw_cap_rsp_pkt_t *cap_r)
{
	int i, bc;
	
	if (!cap_r)
		return -EINVAL;
	if (mv->id == DLSW_MV_CAP_XCHNG_POS_RSP || mv->id != DLSW_MV_CAP_XCHNG_NEG_RSP) {
		cap_r->code[0] = NULL;
		goto out;
	}
	for (i = 0, bc = 0; bc < mv->len; i++, bc += sizeof(dlsw_cap_reason_t)) {
		dlsw_cap_reason_t *cr = (dlsw_cap_reason_t *)(data + bc);
		cap_r->code[i] = (dlsw_cap_reason_t *)calloc(1, sizeof(dlsw_cap_reason_t));
		memcpy(cap_r->code[i], cr, sizeof(dlsw_cap_reason_t));
	}
	cap_r->code[i] = NULL;
out:	return 0;
}

int dlsw_vect_rx_cap_xchng_c_print(sub_vector_t *sv, void *data)
{
	switch (sv->id) {
		case DLSW_SV_VENDOR_ID: {
			unsigned char *oui = data;
			printf("vendor_id: %02X:%02X:%02X\n",
				oui[0], oui[1], oui[2]);
			break;
		}
		case DLSW_SV_VERSION: {
			dlsw_version_t *ver = data;
			printf("version: v%d.%d\n", ver->version, ver->release);
			break;
		}	
		case DLSW_SV_INIT_PACE_WIN: {
			u_int16_t *pace = data;
			printf("init_pace_win: %d\n", ntohs(*pace));
			break;
		}
		case DLSW_SV_VERSION_STRING:
			printf("version_string: ?finish?\n");
			break;
			
		case DLSW_SV_MAC_ADDR_EXCLSV:
			printf("mac_addr_exclsv: ?finish?\n");
			break;
			
		case DLSW_SV_SAP_LIST:
			printf("sap_list: \n%s", dlsw_print_sap_bitmap(data));
			break;
			
		case DLSW_SV_TCP_CONN:
			printf("tcp_conn: ?finish?\n");
			break;
			
		case DLSW_SV_NETBIOS_NAME_EXCLSV:
			printf("netbios_name_exclsv: ?finish?\n");
			break;
			
		case DLSW_SV_MAC_ADDR_LIST:
			printf("mac_addr_list: ?finish?\n");
			break;
			
		case DLSW_SV_NETBIOS_NAME_LIST:
			printf("netbios_name_list: ?finish?\n");
			break;
			
		case DLSW_SV_VENDOR_CONTEXT: {
			unsigned char *oui = data;
			printf("vendor_context: %02X:%02X:%02X\n",
				oui[0], oui[1], oui[2]);
			break;
		}
		default:
			printf(__FUNCTION__ ": unknown sv id (%02X)\n", sv->id);
			return -EINVAL;
	}
	return 0;
}

int dlsw_vect_rx_cap_xchng_c(sub_vector_t *sv, void *data, dlsw_cap_cmd_pkt_t *cap_c)
{
	if (!cap_c)
		return -EINVAL;
	
        switch (sv->id) {
		case DLSW_SV_VENDOR_ID:
			cap_c->vfield |= DLSW_CAP_VFIELD_VENDOR_ID;
			memcpy(&cap_c->vendor_id, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_VERSION:
			cap_c->vfield |= DLSW_CAP_VFIELD_VERSION;
			memcpy(&cap_c->version, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_INIT_PACE_WIN:
			cap_c->vfield |= DLSW_CAP_VFIELD_PACE_WIN;
			memcpy(&cap_c->pace_win, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_VERSION_STRING:
			cap_c->vfield |= DLSW_CAP_VFIELD_VERSION_STRING;
			memcpy(&cap_c->version_string, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_MAC_ADDR_EXCLSV:
			cap_c->vfield |= DLSW_CAP_VFIELD_MAC_ADDR_EXCLSV;
			memcpy(&cap_c->mac_addr_exclsv, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_SAP_LIST:
			cap_c->vfield |= DLSW_CAP_VFIELD_SAP_LIST;
			memcpy(&cap_c->sap_list, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_TCP_CONN:
			cap_c->vfield |= DLSW_CAP_VFIELD_TCP_CONN;
			memcpy(&cap_c->tcp_conn, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_NETBIOS_NAME_EXCLSV:
			cap_c->vfield |= DLSW_CAP_VFIELD_NETBIOS_NAME_EXCLSV;
			memcpy(&cap_c->netbios_name_exclsv, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_MAC_ADDR_LIST:
			cap_c->vfield |= DLSW_CAP_VFIELD_MAC_ADDR;
			memcpy(&cap_c->mac_addr, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_NETBIOS_NAME_LIST:
			cap_c->vfield |= DLSW_CAP_VFIELD_NETBIOS_NAMES;
			memcpy(&cap_c->netbios_names, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		case DLSW_SV_VENDOR_CONTEXT:
			cap_c->vfield |= DLSW_CAP_VFIELD_VENDOR_CONTEXT;
			memcpy(&cap_c->vendor_context, data, DLSW_SV_PAYLOAD(sv));
			break;
			
		default:
			printf(__FUNCTION__ ": unknown sub-vector 0x%02X\n", sv->id);
			break;
	}
	return 0;
}

major_vector_t *dlsw_vect_tx_cap_xchng_c(dlsw_cap_cmd_pkt_t *cap_c)
{
	major_vector_t *mv = NULL;
	mv = dlsw_major_vector_put(htons(DLSW_MV_CAP_XCHNG_CMD), sizeof(*mv));
	if (cap_c->vfield & DLSW_CAP_VFIELD_VENDOR_ID) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_VENDOR_ID,
			sizeof(dlsw_oui_t), &cap_c->vendor_id);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_VERSION) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_VERSION,
			sizeof(dlsw_version_t), &cap_c->version);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_PACE_WIN) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_INIT_PACE_WIN,
			sizeof(dlsw_pace_win_t), &cap_c->pace_win);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_SAP_LIST) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_SAP_LIST,
			sizeof(dlsw_sap_list_t), &cap_c->sap_list);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_VERSION_STRING) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_VERSION_STRING,
			strlen(cap_c->version_string), &cap_c->version_string);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_VENDOR_CONTEXT) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_VENDOR_CONTEXT,
			sizeof(dlsw_oui_t), &cap_c->vendor_context);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_TCP_CONN) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_TCP_CONN,
			sizeof(dlsw_tcp_conn_t), &cap_c->tcp_conn);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_MAC_ADDR_EXCLSV) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_MAC_ADDR_EXCLSV,
			sizeof(dlsw_exclusive_t), &cap_c->mac_addr_exclsv);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_MAC_ADDR) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_MAC_ADDR_LIST,
			sizeof(dlsw_mac_addr_t), &cap_c->mac_addr);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_NETBIOS_NAME_EXCLSV) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_NETBIOS_NAME_EXCLSV,
			sizeof(dlsw_exclusive_t), &cap_c->netbios_name_exclsv);
	}
	if (cap_c->vfield & DLSW_CAP_VFIELD_NETBIOS_NAMES) {
		mv = dlsw_sub_vector_put(mv, DLSW_SV_NETBIOS_NAME_LIST,
			sizeof(dlsw_netbios_names_t), &cap_c->netbios_names);
	}
out:	return mv;
}

major_vector_t *dlsw_vect_tx_cap_xchng_pos_r(void)
{
	major_vector_t *mv = NULL;
	mv = dlsw_major_vector_put(htons(DLSW_MV_CAP_XCHNG_POS_RSP), 
		sizeof(*mv));
out:	return mv;
}

major_vector_t *dlsw_vect_tx_cap_xchng_neg_r(dlsw_cap_rsp_pkt_t *cap_r)
{
	u_int16_t data[4 * DLSW_INVALID_MAX];
	major_vector_t *mv = NULL;
	int i;
	
	if (!cap_r)
		goto out;
	for (i = 0; cap_r->code[i] != NULL; i++);
	i--;
	mv = dlsw_major_vector_put(htons(DLSW_MV_CAP_XCHNG_NEG_RSP), 
		sizeof(*mv) + (sizeof(dlsw_cap_reason_t) * i));
	memcpy((&mv + sizeof(*mv)), cap_r->code, (sizeof(dlsw_cap_reason_t) * i));
out:	return mv;
}
