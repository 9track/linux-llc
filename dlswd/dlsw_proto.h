/* dlsw_proto.h: SSP protocol specific headers.
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

#ifndef _DLSW_PROTO_H
#define _DLSW_PROTO_H

#define SSP_READ_PORT	2065
#define SSP_WRITE_PORT	2067

#define SSP_READ_PORT_BACKLOG	40
#define SSP_WRITE_PORT_BACKLOG	40

typedef struct {
	u_int32_t	port_id;
	u_int32_t	dlc;
} ssp_circuit_id_t;

typedef struct {
	u_int8_t	dst_mac_addr[IFHWADDRLEN];
        u_int8_t      	src_mac_addr[IFHWADDRLEN];
        u_int8_t      	src_sap;
	u_int8_t	dst_sap;
} ssp_data_link_id_t;

typedef struct {
	u_int8_t	version;
	u_int8_t	hdr_len;
	u_int16_t	msg_len;
	u_int32_t	dst_dlc;
	u_int32_t	dst_dlc_port_id;
	u_int16_t	rsv2;
	u_int8_t	msg_type;
	u_int8_t	flow_ctrl;
} ssp_info_t;

typedef struct {
	u_int8_t	proto;
	u_int8_t	hdr_num;
	u_int16_t	rsv0;
	u_int8_t	max_frame_size;
	u_int8_t	ssp_flags;
	u_int8_t	circuit_pri;
	u_int8_t	msg_type;
	u_int8_t	dst_mac_addr[IFHWADDRLEN];
	u_int8_t	src_mac_addr[IFHWADDRLEN];
	u_int8_t	src_sap;
	u_int8_t	dst_sap;
	u_int8_t	direction;
	u_int8_t	rsv1;
	u_int16_t	rsv2;
	u_int16_t	dlc_hdr_len;
	u_int32_t	src_dlc_port_id;
	u_int32_t	src_dlc;
	u_int32_t	src_transport;
	u_int32_t	dst_dlc_port_id;
	u_int32_t	dst_dlc;
	u_int32_t	dst_transport;
	u_int32_t	rsv3;
} ssp_ctrl_t;

#define SSP_VERSION	75
#define SSP_HDR_LEN	72
#define SSP_HDR_NUM	1
#define SSP_PROTO_ID	66

/* frame direction field is set to 0x01 (1) for frames sent from the orgin DLS to
 * the target DLS, and is set to 0x02 (2) for frames sent from the target DLS to
 * the origin DLS.
 */
#define SSP_DIR_ODLS_TDLS	1
#define SSP_DIR_TDLS_ODLS	2

/* message types. */
#define	SSP_CANUREACH		0x03
#define SSP_ICANREACH		0x04
#define SSP_REACH_ACK		0x05
#define SSP_DGRMFRAME		0x06
#define SSP_XIDFRAME		0x07
#define SSP_CONTACT		0x08
#define SSP_CONTACTED		0x09
#define SSP_RESTART_DL		0x10
#define SSP_DL_RESTARTED	0x11
#define SSP_INFOFRAME		0x0A
#define SSP_HALT_DL		0x0E
#define SSP_DL_HALTED		0x0F
#define SSP_NETBIOS_NQ		0x12
#define SSP_NETBIOS_NR		0x13
#define SSP_DATAFRAME		0x14
#define SSP_NETBIOS_ANQ		0x1A
#define SSP_NETBIOS_ANR		0x1B

/* data link switch states. */
enum {
	CIRCUIT_ESTABLISHED = 1,
	CIRCUIT_PENDING,
	CIRCUIT_RESTART,
	CONNECTED,
	CONNECT_PENDING,
	CONTACT_PENDING,
	DISCONNECTED,
	DISCONNECT_PENDING,
	HALT_PENDING,
	RESTART_PENDING,
	RESOLVE_PENDING
} dl_switch_states;

/* local dlc events. */
enum {
	DLC_EVT_CONTACTED = 1,
	DLC_EVT_DGRAM,
	DLC_EVT_ERROR,
	DLC_EVT_INFO,
	DLC_EVT_DL_HALTED,
	DLC_EVT_DL_STARTED,
	DLC_EVT_RESET,
	DLC_EVT_RESOLVE_C,
	DLC_EVT_XID
} local_dlc_events;

/* local dlc actions. */
enum {
	DLC_ACT_CONTACT = 1,
	DLC_ACT_DGRM,
	DLC_ACT_ENTER_BUSY,
	DLC_ACT_EXIT_BUSY,
	DLC_ACT_HALT_DL,
	DLC_ACT_INFO,
	DLC_ACT_RESOLVE_R,
	DLC_ACT_START_DL,
	DLC_ACT_XID
} local_dlc_actions;

struct ssp_router_info {
	struct ssp_router_info *next;

	int	read_fd;
	int	write_fd;
};

#endif	/* _DLSW_PROTO_H */
