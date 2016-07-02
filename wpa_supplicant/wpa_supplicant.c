#include <FreeRTOS.h>
#include "os.h"
#include "list.h"

#include "common.h"
#include "wpa.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "driver.h"

/**
 * wpa_supplicant_rx_eapol - Deliver a received EAPOL frame to wpa_supplicant
 * @ctx: Context pointer (wpa_s); this is the ctx variable registered
 *	with struct wpa_driver_ops::init()
 * @src_addr: Source address of the EAPOL frame
 * @buf: EAPOL data starting from the EAPOL header (i.e., no Ethernet header)
 * @len: Length of the EAPOL data
 *
 * This function is called for each received EAPOL frame. Most driver
 * interfaces rely on more generic OS mechanism for receiving frames through
 * l2_packet, but if such a mechanism is not available, the driver wrapper may
 * take care of received EAPOL frames and deliver them to the core supplicant
 * code by calling this function.
 */
void wpa_supplicant_rx_eapol(void *ctx, const u8 *src_addr,
			     const u8 *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_dbg(wpa_s, MSG_DEBUG, "RX EAPOL from " MACSTR, MAC2STR(src_addr));
	wpa_hexdump(MSG_MSGDUMP, "RX EAPOL", buf, len);

#ifdef CONFIG_PEERKEY
	if (wpa_s->wpa_state > WPA_ASSOCIATED && wpa_s->current_ssid &&
	    wpa_s->current_ssid->peerkey &&
	    !(wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE) &&
	    wpa_sm_rx_eapol_peerkey(wpa_s->wpa, src_addr, buf, len) == 1) {
		wpa_dbg(wpa_s, MSG_DEBUG, "RSN: Processed PeerKey EAPOL-Key");
		return;
	}
#endif /* CONFIG_PEERKEY */

	if (wpa_s->wpa_state < WPA_ASSOCIATED ||
	    (wpa_s->last_eapol_matches_bssid &&
#ifdef CONFIG_AP
	     !wpa_s->ap_iface &&
#endif /* CONFIG_AP */
	     os_memcmp(src_addr, wpa_s->bssid, ETH_ALEN) != 0)) {
		/*
		 * There is possible race condition between receiving the
		 * association event and the EAPOL frame since they are coming
		 * through different paths from the driver. In order to avoid
		 * issues in trying to process the EAPOL frame before receiving
		 * association information, lets queue it for processing until
		 * the association event is received. This may also be needed in
		 * driver-based roaming case, so also use src_addr != BSSID as a
		 * trigger if we have previously confirmed that the
		 * Authenticator uses BSSID as the src_addr (which is not the
		 * case with wired IEEE 802.1X).
		 */
		wpa_dbg(wpa_s, MSG_DEBUG, "Not associated - Delay processing "
			"of received EAPOL frame (state=%s bssid=" MACSTR ")",
			wpa_supplicant_state_txt(wpa_s->wpa_state),
			MAC2STR(wpa_s->bssid));
		wpabuf_free(wpa_s->pending_eapol_rx);
		wpa_s->pending_eapol_rx = wpabuf_alloc_copy(buf, len);
		if (wpa_s->pending_eapol_rx) {
//			os_get_reltime(&wpa_s->pending_eapol_rx_time);
			os_memcpy(wpa_s->pending_eapol_rx_src, src_addr,
				  ETH_ALEN);
		}
		return;
	}

	wpa_s->last_eapol_matches_bssid =
		os_memcmp(src_addr, wpa_s->bssid, ETH_ALEN) == 0;

#ifdef CONFIG_AP
	if (wpa_s->ap_iface) {
		wpa_supplicant_ap_rx_eapol(wpa_s, src_addr, buf, len);
		return;
	}
#endif /* CONFIG_AP */

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
		wpa_dbg(wpa_s, MSG_DEBUG, "Ignored received EAPOL frame since "
			"no key management is configured");
		return;
	}

	if (wpa_s->eapol_received == 0 &&
	    (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE) ||
	     !wpa_key_mgmt_wpa_psk(wpa_s->key_mgmt) ||
	     wpa_s->wpa_state != WPA_COMPLETED) &&
	    (wpa_s->current_ssid == NULL ||
	     wpa_s->current_ssid->mode != IEEE80211_MODE_IBSS)) {
		/* Timeout for completing IEEE 802.1X and WPA authentication */
		int timeout = 10;

		if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt) ||
		    wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA ||
		    wpa_s->key_mgmt == WPA_KEY_MGMT_WPS) {
			/* Use longer timeout for IEEE 802.1X/EAP */
			timeout = 70;
		}

#ifdef CONFIG_WPS
		if (wpa_s->current_ssid && wpa_s->current_bss &&
		    (wpa_s->current_ssid->key_mgmt & WPA_KEY_MGMT_WPS) &&
		    eap_is_wps_pin_enrollee(&wpa_s->current_ssid->eap)) {
			/*
			 * Use shorter timeout if going through WPS AP iteration
			 * for PIN config method with an AP that does not
			 * advertise Selected Registrar.
			 */
			struct wpabuf *wps_ie;

			wps_ie = wpa_bss_get_vendor_ie_multi(
				wpa_s->current_bss, WPS_IE_VENDOR_TYPE);
			if (wps_ie &&
			    !wps_is_addr_authorized(wps_ie, wpa_s->own_addr, 1))
				timeout = 10;
			wpabuf_free(wps_ie);
		}
#endif /* CONFIG_WPS */

//		wpa_supplicant_req_auth_timeout(wpa_s, timeout, 0);
	}
	wpa_s->eapol_received++;

	if (wpa_s->countermeasures) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Countermeasures - dropped "
			"EAPOL packet");
		return;
	}

#ifdef CONFIG_IBSS_RSN
	if (wpa_s->current_ssid &&
	    wpa_s->current_ssid->mode == WPAS_MODE_IBSS) {
		ibss_rsn_rx_eapol(wpa_s->ibss_rsn, src_addr, buf, len);
		return;
	}
#endif /* CONFIG_IBSS_RSN */

	/* Source address of the incoming EAPOL frame could be compared to the
	 * current BSSID. However, it is possible that a centralized
	 * Authenticator could be using another MAC address than the BSSID of
	 * an AP, so just allow any address to be used for now. The replies are
	 * still sent to the current BSSID (if available), though. */

	os_memcpy(wpa_s->last_eapol_src, src_addr, ETH_ALEN);
//	if (!wpa_key_mgmt_wpa_psk(wpa_s->key_mgmt) &&
//	    eapol_sm_rx_eapol(wpa_s->eapol, src_addr, buf, len) > 0)
//		return;
//	wpa_drv_poll(wpa_s);
	if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE))
		wpa_sm_rx_eapol(wpa_s->wpa, src_addr, buf, len);
	else if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt)) {
		/*
		 * Set portValid = TRUE here since we are going to skip 4-way
		 * handshake processing which would normally set portValid. We
		 * need this to allow the EAPOL state machines to be completed
		 * without going through EAPOL-Key handshake.
		 */
//		eapol_sm_notify_portValid(wpa_s->eapol, TRUE);
	}
}
