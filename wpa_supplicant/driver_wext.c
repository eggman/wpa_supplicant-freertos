/*
 * Driver interaction with generic Linux Wireless Extensions
 * Copyright (c) 2003-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file implements a driver interface for the Linux Wireless Extensions.
 * When used with WE-18 or newer, this interface can be used as-is with number
 * of drivers. In addition to this, some of the common functions in this file
 * can be used by other driver interface implementations that use generic WE
 * ioctls, but require private ioctls for some of the functionality.
 */

#include "includes.h"
//#include <sys/ioctl.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <fcntl.h>
//#include <net/if_arp.h>
//#include <dirent.h>

//#include "linux_wext.h"
#include "common.h"
//#include "eloop.h"
//#include "common/ieee802_11_defs.h"
//#include "common/wpa_common.h"
//#include "priv_netlink.h"
//#include "netlink.h"
//#include "linux_ioctl.h"
//#include "rfkill.h"
//#include "driver.h"
//#include "driver_wext.h"

#include "wpa.h"

static int errno;
#define  EOPNOTSUPP  95  /* Operation not supported on transport endpoint */
#define  ENODEV    19  /* No such device */

static int wpa_driver_wext_set_key_ext(void *priv, enum wpa_alg alg,
				       const u8 *addr, int key_idx,
				       int set_tx, const u8 *seq,
				       size_t seq_len,
				       const u8 *key, size_t key_len)
{
	struct wpa_driver_wext_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;
	struct iw_encode_ext *ext;

	if (seq_len > IW_ENCODE_SEQ_MAX_SIZE) {
		wpa_printf(MSG_DEBUG, "%s: Invalid seq_len %lu",
			   __FUNCTION__, (unsigned long) seq_len);
		return -1;
	}

	ext = os_zalloc(sizeof(*ext) + key_len);
	if (ext == NULL)
		return -1;
	os_memset(&iwr, 0, sizeof(iwr));
//	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ); //todo
	iwr.u.encoding.flags = key_idx + 1;
	iwr.u.encoding.flags |= IW_ENCODE_TEMP;
	if (alg == WPA_ALG_NONE)
		iwr.u.encoding.flags |= IW_ENCODE_DISABLED;
	iwr.u.encoding.pointer = (void *) ext;
	iwr.u.encoding.length = sizeof(*ext) + key_len;

	if (addr == NULL || is_broadcast_ether_addr(addr))
		ext->ext_flags |= IW_ENCODE_EXT_GROUP_KEY;
	if (set_tx)
		ext->ext_flags |= IW_ENCODE_EXT_SET_TX_KEY;

	ext->addr.sa_family = ARPHRD_ETHER;
	if (addr)
		os_memcpy(ext->addr.sa_data, addr, ETH_ALEN);
	else
		os_memset(ext->addr.sa_data, 0xff, ETH_ALEN);
	if (key && key_len) {
		os_memcpy(ext + 1, key, key_len);
		ext->key_len = key_len;
	}
	switch (alg) {
	case WPA_ALG_NONE:
		ext->alg = IW_ENCODE_ALG_NONE;
		break;
	case WPA_ALG_WEP:
		ext->alg = IW_ENCODE_ALG_WEP;
		break;
	case WPA_ALG_TKIP:
		ext->alg = IW_ENCODE_ALG_TKIP;
		break;
	case WPA_ALG_CCMP:
		ext->alg = IW_ENCODE_ALG_CCMP;
		break;
	case WPA_ALG_PMK:
		ext->alg = IW_ENCODE_ALG_PMK;
		break;
#ifdef CONFIG_IEEE80211W
	case WPA_ALG_IGTK:
		ext->alg = IW_ENCODE_ALG_AES_CMAC;
		break;
#endif /* CONFIG_IEEE80211W */
	default:
		wpa_printf(MSG_DEBUG, "%s: Unknown algorithm %d",
			   __FUNCTION__, alg);
		os_free(ext);
		return -1;
	}

	if (seq && seq_len) {
		ext->ext_flags |= IW_ENCODE_EXT_RX_SEQ_VALID;
		os_memcpy(ext->rx_seq, seq, seq_len);
	}
#if 0
	if (ioctl(drv->ioctl_sock, SIOCSIWENCODEEXT, &iwr) < 0) {
		ret = errno == EOPNOTSUPP ? -2 : -1;
		if (errno == ENODEV) {
			/*
			 * ndiswrapper seems to be returning incorrect error
			 * code.. */
			ret = -2;
		}

		wpa_printf(MSG_ERROR, "ioctl[SIOCSIWENCODEEXT]: %s",
			   strerror(errno));
	}
#else
//todo
#endif

	os_free(ext);
	return ret;
}


