/* lar_vector.c: generic vector functions for the lar protocol.
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
#include "lar.h"
#include "lar_vector.h"

major_vector_t *lar_vect_tx_notify(lar_notify_pkt_t *notify)
{
	major_vector_t *mv = NULL;
	int i;

	if (!notify)
		goto out;
	mv = lar_major_vector_put(LAR_MV_NOTIFY, LAR_MV_T_LEN);
        mv = lar_sub_vector_put(mv, LAR_SV_CORRELATOR,
                sizeof(lar_correlator_t), &notify->correlator);
	mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_LSAP,
        	sizeof(lar_lsap_t), &notify->lsap);
        mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_MAC,
                LAR_MAX_SV_MAC_LEN, notify->mac);
        mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_NETID,
                LAR_MAX_SV_NETID_LEN, notify->netid);
        mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_NAME,
                LAR_MAX_SV_NAME_LEN, notify->name);
	if(notify->groups[0] != NULL) {
                major_vector_t *gv;
                gv = lar_major_vector_put(LAR_SV_GROUP_NAMES, LAR_MV_T_LEN);
                for(i = 0; notify->groups[i] != NULL; i++) {
                        gv = lar_sub_vector_put(gv, LAR_SV_GROUP_NAME,
                                LAR_MAX_SV_GROUP_LEN, notify->groups[i]);
                }
                mv = lar_sub_vector_put(mv, LAR_SV_GROUP_NAMES,
                        LAR_MV_PAYLOAD(gv, 0), LAR_MV_DATA(gv));
                free(gv);
        }
        mv = lar_sub_vector_put(mv, LAR_SV_RTCAP,
                sizeof(lar_rtcap_t), &notify->rtcap);
        mv = lar_sub_vector_put(mv, LAR_SV_RETURN_CCE_MAC,
                LAR_MAX_SV_MAC_LEN, notify->cce_mac);
out:	return mv;
}

major_vector_t *lar_vect_tx_query(lar_query_pkt_t *query)
{
	major_vector_t *mv = NULL;

	if (!query)
		goto out;
        mv = lar_major_vector_put(LAR_MV_QUERY, LAR_MV_T_LEN);
        mv = lar_sub_vector_put(mv, LAR_SV_CORRELATOR,
                sizeof(lar_correlator_t), &query->correlator);
        mv = lar_sub_vector_put(mv, LAR_SV_TARGET_NETID,
                LAR_MAX_SV_NETID_LEN, query->netid);
        mv = lar_sub_vector_put(mv, LAR_SV_GROUP_NAME,
                LAR_MAX_SV_GROUP_LEN, query->group);
        mv = lar_sub_vector_put(mv, LAR_SV_RTCAP, 
                sizeof(lar_rtcap_t), &query->rtcap);
	mv = lar_sub_vector_put(mv, LAR_SV_RETURN_CCE_MAC,
                        LAR_MAX_SV_MAC_LEN, query->cce_mac);
out:	return mv;
}

major_vector_t *lar_vect_tx_found(lar_found_pkt_t *found)
{
	major_vector_t *mv = NULL;

	if (!found)
		goto out;
	mv = lar_major_vector_put(LAR_MV_FOUND, LAR_MV_T_LEN);
        mv = lar_sub_vector_put(mv, LAR_SV_CORRELATOR,
                sizeof(lar_correlator_t), &found->correlator);
        mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_LSAP,
                sizeof(lar_lsap_t), &found->lsap);
        mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_MAC,
                LAR_MAX_SV_MAC_LEN, found->mac);
out:	return mv;
}

major_vector_t *lar_vect_tx_find(lar_find_pkt_t *find)
{
	major_vector_t *mv = NULL;

	if (!find)
		goto out;
	mv = lar_major_vector_put(LAR_MV_FIND, LAR_MV_T_LEN);
        mv = lar_sub_vector_put(mv, LAR_SV_CORRELATOR,
        	sizeof(lar_correlator_t), &find->correlator);
        mv = lar_sub_vector_put(mv, LAR_SV_TARGET_NETID,
                LAR_MAX_SV_NETID_LEN, find->tnetid);
        mv = lar_sub_vector_put(mv, LAR_SV_TARGET_NAME,
                LAR_MAX_SV_NAME_LEN, find->tname);
	mv = lar_sub_vector_put(mv, LAR_SV_ORIGIN_NETID,
		LAR_MAX_SV_NETID_LEN, find->onetid);
        mv = lar_sub_vector_put(mv, LAR_SV_ORIGIN_NAME,
		LAR_MAX_SV_NAME_LEN, find->oname);
        mv = lar_sub_vector_put(mv, LAR_SV_ORIGIN_LSAP, 
                sizeof(lar_lsap_t), &find->olsap);
        mv = lar_sub_vector_put(mv, LAR_SV_ORIGIN_MAC,
		LAR_MAX_SV_MAC_LEN, find->omac);
        mv = lar_sub_vector_put(mv, LAR_SV_ORIGIN_CCE_MAC,
		LAR_MAX_SV_MAC_LEN, find->cce_mac);
out:	return mv;
}

major_vector_t *lar_vect_tx_advertise(lar_advertise_pkt_t *adv)
{
	major_vector_t *mv = NULL;
	int i;

	if (!adv)
		goto out;
	mv = lar_major_vector_put(LAR_MV_ADVERTISE, LAR_MV_T_LEN);
	mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_NETID,
                LAR_MAX_SV_NETID_LEN, adv->netid);
        mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_NAME,
                LAR_MAX_SV_NAME_LEN, adv->name);
        mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_LSAP,
                sizeof(lar_lsap_t), &adv->lsap);
        mv = lar_sub_vector_put(mv, LAR_SV_RESOURCE_MAC,
                LAR_MAX_SV_MAC_LEN, adv->mac);
	mv = lar_sub_vector_put(mv, LAR_SV_RTCAP,
                sizeof(lar_rtcap_t), &adv->rtcap);
	mv = lar_sub_vector_put(mv, LAR_SV_CONN_NETID,
		sizeof(lar_conn_netid_t), adv->conn_netid);
        if(adv->groups[0] != NULL) {
                major_vector_t *gv;
                gv = lar_major_vector_put(LAR_SV_GROUP_NAMES, LAR_MV_T_LEN);
                for(i = 0; adv->groups[i] != NULL; i++) {
                        gv = lar_sub_vector_put(gv, LAR_SV_GROUP_NAME,
                                LAR_MAX_SV_GROUP_LEN, adv->groups[i]);
                }
                mv = lar_sub_vector_put(mv, LAR_SV_GROUP_NAMES,
                        LAR_MV_PAYLOAD(gv, 0), LAR_MV_DATA(gv));
                free(gv);
        }
        mv = lar_sub_vector_put(mv, LAR_SV_RETURN_CCE_MAC,
                LAR_MAX_SV_MAC_LEN, adv->cce_mac);
out:	return mv;
}

major_vector_t *lar_vect_tx_solicit(lar_solicit_pkt_t *solicit)
{
	major_vector_t *mv = NULL;

	if (!solicit)
		goto out;
	mv = lar_major_vector_put(LAR_MV_SOLICIT, LAR_MV_T_LEN);
	mv = lar_sub_vector_put(mv, LAR_SV_TARGET_NETID,
		sizeof(lar_netid_t), solicit->netid);
	mv = lar_sub_vector_put(mv, LAR_SV_GROUP_NAME,
		sizeof(lar_group_t), solicit->group);
out:	return mv;
}

int lar_vect_rx_group_names(sub_vector_t *sv, void *data, lar_group_t **groups)
{
        lar_group_t *g = data;
        int i;
              
        for(i = 0; i < LAR_MAX_SV_GROUP_NAMES; i++) {
                if(groups[i] == NULL)
                        break;
        }               
        if(i == LAR_MAX_SV_GROUP_NAMES) {
                printf("exhausted maximum group entries (%d)\n", i);
                return -EUSERS;
        }       
        groups[i] = calloc(1, sizeof(lar_group_t));
        if(!groups[i]) 
                return -ENOMEM;
        memcpy(groups[i], g, sizeof(lar_group_t));
	groups[i + 1] = NULL;
        return 0;
}       

int lar_vect_rx_notify(sub_vector_t *sv, void *data, lar_notify_pkt_t *notify)
{       
        switch (sv->id) {
                case LAR_SV_CORRELATOR:
                        memcpy(&notify->correlator, data, LAR_SV_PAYLOAD(sv));
                        break;
                
                case LAR_SV_RESOURCE_LSAP:
                        memcpy(&notify->lsap, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RESOURCE_MAC:
                        memcpy(notify->mac, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RESOURCE_NETID:
			notify->netid_len = LAR_SV_PAYLOAD(sv);
                        memcpy(notify->netid, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RESOURCE_NAME:
			notify->name_len = LAR_SV_PAYLOAD(sv);
                        memcpy(notify->name, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_GROUP_NAMES:
                	lar_ssub_vector_parse(sv, lar_vect_rx_group_names, 
				notify->groups);
                        break;

                case LAR_SV_RTCAP:
                        memcpy(&notify->rtcap, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RETURN_CCE_MAC:
                        memcpy(notify->mac, data, LAR_SV_PAYLOAD(sv));
                        break;

                default:
                        printf("notify: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }
        return 0;
}

int lar_vect_rx_query(sub_vector_t *sv, void *data, lar_query_pkt_t *query)
{
        switch (sv->id) {
                case LAR_SV_CORRELATOR:
                        memcpy(&query->correlator, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_TARGET_NETID:
			query->netid_len = LAR_SV_PAYLOAD(sv);
                        memcpy(query->netid, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_GROUP_NAME:
			query->group_len = LAR_SV_PAYLOAD(sv);
                        memcpy(query->group, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RTCAP:
                        memcpy(&query->rtcap, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RETURN_CCE_MAC:
                        memcpy(query->cce_mac, data, LAR_SV_PAYLOAD(sv));
                        break;

                default:
                        printf("query: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }
        return 0;
}

int lar_vect_rx_found(sub_vector_t *sv, void *data, lar_found_pkt_t *found)
{
        switch (sv->id) {
                case LAR_SV_CORRELATOR:
                        memcpy(&found->correlator, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_RESOURCE_LSAP:
                        memcpy(&found->lsap, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_RESOURCE_MAC:
                        memcpy(found->mac, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                default:
                        printf("found: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }               
        return 0;
}

int lar_vect_rx_find(sub_vector_t *sv, void *data, lar_find_pkt_t *find)
{
        switch (sv->id) {
                case LAR_SV_CORRELATOR:
                        memcpy(&find->correlator, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_TARGET_NETID:
			find->tnetid_len = LAR_SV_PAYLOAD(sv);
                        memcpy(find->tnetid, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_TARGET_NAME:
			find->tname_len = LAR_SV_PAYLOAD(sv);
                        memcpy(find->tname, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_ORIGIN_NETID:
			find->onetid_len = LAR_SV_PAYLOAD(sv);
                        memcpy(find->onetid, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_ORIGIN_NAME:
			find->oname_len = LAR_SV_PAYLOAD(sv);
                        memcpy(find->oname, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_ORIGIN_LSAP:
                        memcpy(&find->olsap, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_ORIGIN_MAC:
                        memcpy(find->omac, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_ORIGIN_CCE_MAC:
                        memcpy(find->cce_mac, data, LAR_SV_PAYLOAD(sv));
                        break;

                default:
                        printf("find: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }
        return 0;
}

int lar_vect_rx_advertise(sub_vector_t *sv, void *data, lar_advertise_pkt_t *adv)
{
        switch (sv->id) {
                case LAR_SV_RESOURCE_NETID:
			adv->netid_len = LAR_SV_PAYLOAD(sv);
                        memcpy(adv->netid, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RESOURCE_NAME:
			adv->name_len = LAR_SV_PAYLOAD(sv);
                        memcpy(adv->name, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RESOURCE_LSAP:
                        memcpy(&adv->lsap, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RESOURCE_MAC:
                        memcpy(adv->mac, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_RTCAP:
                        memcpy(&adv->rtcap, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_CONN_NETID:
			adv->conn_netid_len = LAR_SV_PAYLOAD(sv);
                        memcpy(adv->conn_netid, data, LAR_SV_PAYLOAD(sv));
                        break;

                case LAR_SV_GROUP_NAMES:
                        lar_ssub_vector_parse(sv, lar_vect_rx_group_names, adv->groups);
                        break;

                case LAR_SV_RETURN_CCE_MAC:
                        memcpy(adv->cce_mac, data, LAR_SV_PAYLOAD(sv));
                        break;

                default:
                        printf("advertise: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }
        return 0;
}

int lar_vect_rx_solicit(sub_vector_t *sv, void *data, lar_solicit_pkt_t *sol)
{
        switch (sv->id) {
                case LAR_SV_TARGET_NETID:
			sol->netid_len = LAR_SV_PAYLOAD(sv);
                        memcpy(sol->netid, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                case LAR_SV_GROUP_NAME:
			sol->group_len = LAR_SV_PAYLOAD(sv);
                        memcpy(sol->group, data, LAR_SV_PAYLOAD(sv));
                        break;
                        
                default:
                        printf("solicit: unknown sub-vector 0x%02X\n", sv->id);
                        break;
        }               
        return 0;
}       
