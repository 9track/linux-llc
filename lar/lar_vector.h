/* lar_vector.h: Lan address resolution vector structures defintions.
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

#ifndef _LAR_VECTOR_H
#define _LAR_VECTOR_H

extern major_vector_t *lar_vect_tx_notify(lar_notify_pkt_t *notify);
extern major_vector_t *lar_vect_tx_query(lar_query_pkt_t *query);
extern major_vector_t *lar_vect_tx_found(lar_found_pkt_t *found);
extern major_vector_t *lar_vect_tx_find(lar_find_pkt_t *find);
extern major_vector_t *lar_vect_tx_advertise(lar_advertise_pkt_t *adv);
extern major_vector_t *lar_vect_tx_solicit(lar_solicit_pkt_t *solicit);

extern int lar_vect_rx_notify(sub_vector_t *sv, void *data, 
	lar_notify_pkt_t *notify);
extern int lar_vect_rx_query(sub_vector_t *sv, void *data, 
	lar_query_pkt_t *query);
extern int lar_vect_rx_found(sub_vector_t *sv, void *data, 
	lar_found_pkt_t *found);
extern int lar_vect_rx_find(sub_vector_t *sv, void *data, 
	lar_find_pkt_t *find);
extern int lar_vect_rx_advertise(sub_vector_t *sv, void *data, 
	lar_advertise_pkt_t *adv);
extern int lar_vect_rx_solicit(sub_vector_t *sv, void *data, 
	lar_solicit_pkt_t *sol);
extern int lar_vect_rx_group_names(sub_vector_t *sv, void *data, 
	lar_group_t **groups);
#endif	/* _LAR_VECTOR_H */
