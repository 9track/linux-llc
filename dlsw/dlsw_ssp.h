/* dlsw_ssp.h: SSP protocol specific headers.
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

#ifndef _DLSW_SSP_H
#define _DLSW_SSP_H

#define SSP_READ_PORT_BACKLOG	40

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
	u_int8_t	version;		/* version. 				*/
	u_int8_t	hdrlen;			/* header length. 			*/
	u_int16_t	msglen;			/* message length. 			*/
	u_int32_t	rdlcr;			/* remote data-link correlator. 	*/
	u_int32_t	rdlc_pid;		/* remote data-link control port id. 	*/
	u_int16_t	rsv0;			/* reserved for future use. 		*/
	u_int8_t	msgtype;		/* message type. 			*/
	u_int8_t	flowctrl;		/* flow-control byte. 			*/
	u_int8_t	data[0];		/* data hangs off the end.		*/
} ssp_info_t;

typedef struct {
	u_int8_t        version;                /* version.                             */
        u_int8_t        hdrlen;                 /* header length.                       */
        u_int16_t       msglen;                 /* message length.                      */
        u_int32_t       rdlcr;                  /* remote data-link correlator.         */
        u_int32_t       rdlc_pid;               /* remote data-link control port id.    */
        u_int16_t       rsv0;                   /* reserved for future use.             */
        u_int8_t        msgtype;                /* message type.                        */
        u_int8_t        flowctrl;               /* flow-control byte.                   */
 	u_int8_t	proto;			/* protocol id. 			*/
	u_int8_t	hdrnum;			/* header number. 			*/
	u_int16_t	rsv1;			/* reserved for future use. 		*/
	u_int8_t	lfs;			/* largest frame size. 			*/
	u_int8_t	flags;			/* ssp flags. 				*/
	u_int8_t	priority;		/* circuit priority. 			*/
	u_int8_t	oldmsgtype;		/* old message type. (unused)		*/
	u_int8_t	tmac_addr[IFHWADDRLEN];	/* target mac address.	 		*/
	u_int8_t	omac_addr[IFHWADDRLEN];	/* origin mac address. 			*/
	u_int8_t	osap;			/* origin link service access point. 	*/
	u_int8_t	tsap;			/* target link service access point. 	*/
	u_int8_t	fdir;			/* frame direction. 			*/
	u_int8_t	rsv2;			/* reserved for future use.		*/
	u_int16_t	rsv3;			/* reserved for future use. 		*/
	u_int16_t	dlchdrlen;		/* data link control header length. 	*/
	u_int32_t	odlc_pid;		/* origin data link control port id. 	*/
	u_int32_t	odlcr;			/* origin data link correlator. 	*/
	u_int32_t	otp;			/* origin transport id. 		*/
	u_int32_t	tdlc_pid;		/* target data link control port id. 	*/
	u_int32_t	tdlcr;			/* target data link correlator. 	*/
	u_int32_t	ttp;			/* target transport id. 		*/
	u_int32_t	rsv4;			/* reserved for future use. 		*/
	u_int8_t	data[0];		/* data hands off the end.		*/
} ssp_ctrl_t;

/* general definitions for the ssp information and control structures.
 */
#define SSP_VERSION_1			0x31
#define SSP_VERSION_2			0x32
#define SSP_VERSION_IBM6611		0x4B
#define SSP_HDRLEN_CTRL			0x48
#define SSP_HDRLEN_INFO			0x10
#define SSP_HDRNUM			0x01
#define SSP_PROTO_ID			0x42
#define SSP_DLCHDRLEN_SNA		0x00
#define SSP_DLCHDRLEN_NETBIOS		0x23
#define SSP_FLAGS_EXPLORER		0x80

/* frame direction field is set to 0x01 (1) for frames sent from the orgin DLS to
 * the target DLS, and is set to 0x02 (2) for frames sent from the target DLS to
 * the origin DLS.
 */
#define SSP_DIR_REQ			0x01
#define SSP_DIR_RSP			0x02

/* message types. 
 */
#define	SSP_MSG_CANUREACH		0x03
#define SSP_MSG_ICANREACH		0x04
#define SSP_MSG_REACH_ACK		0x05
#define SSP_MSG_DGRMFRAME		0x06
#define SSP_MSG_XIDFRAME		0x07
#define SSP_MSG_CONTACT			0x08
#define SSP_MSG_CONTACTED		0x09
#define SSP_MSG_RESTART_DL		0x10
#define SSP_MSG_DL_RESTARTED		0x11
#define SSP_MSG_ENTER_BUSY		0x0C
#define SSP_MSG_EXIT_BUSY		0x0D
#define SSP_MSG_INFOFRAME		0x0A
#define SSP_MSG_HALT_DL			0x0E
#define SSP_MSG_DL_HALTED		0x0F
#define SSP_MSG_NETBIOS_NQ		0x12
#define SSP_MSG_NETBIOS_NR		0x13
#define SSP_MSG_DATAFRAME		0x14
#define SSP_MSG_HALT_DL_NOACK		0x19
#define SSP_MSG_NETBIOS_ANQ		0x1A
#define SSP_MSG_NETBIOS_ANR		0x1B
#define SSP_MSG_KEEPALIVE		0x1D
#define SSP_MSG_CAP_EXCHANGE		0x20
#define SSP_MSG_IFCM			0x21
#define SSP_MSG_TEST_CIRCUIT_REQ	0x7A
#define SSP_MSG_TEST_CIRCUIT_RSP	0x7B

/* circuit priority.
 */
#define SSP_PRI_UNSUPPORTED		0x00
#define SSP_PRI_LOW			0x01
#define SSP_PRI_MEDIUM			0x02
#define SSP_PRI_HIGH			0x03
#define SSP_PRI_HIGHEST			0x04

/* data link switch states. */
enum {
	CIRCUIT_ESTABLISHED = 1,
	CIRCUIT_PENDING,
	CIRCUIT_RESTART,
	CIRCUIT_START,
	CONNECTED,
	CONNECT_PENDING,
	CONTACT_PENDING,
	DISCONNECTED,
	DISCONNECT_PENDING,
	HALT_PENDING,
	HALT_PENDING_NOACK,
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
	DLC_EVT_XID,
	DLC_EVT_XPORT_FAILURE,
	DLC_EVT_CS_TIMER_EXP
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

extern int dlsw_ssp_dump_info(ssp_info_t *ssp);
extern int dlsw_ssp_dump_ctrl(ssp_ctrl_t *ssp);

#endif	/* _DLSW_SSP_H */
