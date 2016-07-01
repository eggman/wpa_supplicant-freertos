/*
 * WPA Supplicant - Glue code to setup EAPOL and RSN modules
 * Copyright (c) 2003-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <FreeRTOS.h>
#include "os.h"
#include "list.h"

#include "common.h"
//#include "eapol_supp/eapol_supp_sm.h"
#include "wpa.h"
//#include "eloop.h"
#include "config.h"
//#include "l2_packet/l2_packet.h"
//#include "common/wpa_common.h"
#include "wpa_supplicant_i.h"
//#include "driver_i.h"
//#include "rsn_supp/pmksa_cache.h"
//#include "sme.h"
#include "eapol_common.h"
#include "defs.h"
#include "ieee802_11_defs.h"
//#include "common/wpa_ctrl.h"
//#include "wpas_glue.h"
//#include "wps_supplicant.h"
//#include "bss.h"
//#include "scan.h"
//#include "notify.h"
//#include "wpas_kay.h"


#if defined(IEEE8021X_EAPOL) || !defined(CONFIG_NO_WPA)
static u8 * wpa_alloc_eapol(const struct wpa_supplicant *wpa_s, u8 type,
			    const void *data, u16 data_len,
			    size_t *msg_len, void **data_pos)
{
	struct ieee802_1x_hdr *hdr;

	*msg_len = sizeof(*hdr) + data_len;
	hdr = os_malloc(*msg_len);
	if (hdr == NULL)
		return NULL;

	hdr->version = wpa_s->conf->eapol_version;
	hdr->type = type;
	hdr->length = host_to_be16(data_len);

	if (data)
		os_memcpy(hdr + 1, data, data_len);
	else
		os_memset(hdr + 1, 0, data_len);

	if (data_pos)
		*data_pos = hdr + 1;

	return (u8 *) hdr;
}


/**
 * wpa_ether_send - Send Ethernet frame
 * @wpa_s: Pointer to wpa_supplicant data
 * @dest: Destination MAC address
 * @proto: Ethertype in host byte order
 * @buf: Frame payload starting from IEEE 802.1X header
 * @len: Frame payload length
 * Returns: >=0 on success, <0 on failure
 */
static int wpa_ether_send(struct wpa_supplicant *wpa_s, const u8 *dest,
			  u16 proto, const u8 *buf, size_t len)
{
#ifdef CONFIG_TESTING_OPTIONS
	if (wpa_s->ext_eapol_frame_io && proto == ETH_P_EAPOL) {
		size_t hex_len = 2 * len + 1;
		char *hex = os_malloc(hex_len);

		if (hex == NULL)
			return -1;
		wpa_snprintf_hex(hex, hex_len, buf, len);
		wpa_msg(wpa_s, MSG_INFO, "EAPOL-TX " MACSTR " %s",
			MAC2STR(dest), hex);
		os_free(hex);
		return 0;
	}
#endif /* CONFIG_TESTING_OPTIONS */

//	if (wpa_s->l2) {
//		return l2_packet_send(wpa_s->l2, dest, proto, buf, len);
//	}

	return -1;
}
#endif /* IEEE8021X_EAPOL || !CONFIG_NO_WPA */


static u8 * _wpa_alloc_eapol(void *wpa_s, u8 type,
			     const void *data, u16 data_len,
			     size_t *msg_len, void **data_pos)
{
	return wpa_alloc_eapol(wpa_s, type, data, data_len, msg_len, data_pos);
}


static int _wpa_ether_send(void *wpa_s, const u8 *dest, u16 proto,
const u8 *buf, size_t len)
{
return wpa_ether_send(wpa_s, dest, proto, buf, len);
}


int wpa_supplicant_init_wpa(struct wpa_supplicant *wpa_s)
{
#ifndef CONFIG_NO_WPA
	struct wpa_sm_ctx *ctx;
	ctx = os_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		wpa_printf(MSG_ERROR, "Failed to allocate WPA context.");
		return -1;
	}

	ctx->ether_send = _wpa_ether_send;
	ctx->alloc_eapol = _wpa_alloc_eapol;

#endif /* CONFIG_NO_WPA */

	return 0;
}


