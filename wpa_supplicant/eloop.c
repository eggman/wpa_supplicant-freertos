#include <FreeRTOS.h>

#include "common.h"

#include "ethernet.h"

#define MAXEAPOLBUFLEN 	512
void wpa_auth_data_input(char * data, int len)
{
    struct ether_header *eh;
    char eapolbuf[MAXEAPOLBUFLEN];
    char MacBuf[ETH_ALEN];

    memcpy(eapolbuf, data, len);
	eapolbuf[len] = 0;

    eh = (struct ether_header *)eapolbuf;

    if (memcmp((const char *)eh->ether_dhost, (const char *)MacBuf, ETH_ALEN))
    {
        return;
    }
    wpa_supplicant_rx_eapol(NULL, eh->ether_shost, (char *)&eh[1], len - sizeof(struct ether_header));

    return;
}
