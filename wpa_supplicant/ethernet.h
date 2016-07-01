#ifndef _NET_ETHERNET_H_
#define _NET_ETHERNET_H_

#define	ETHER_ADDR_LEN		6

struct ether_header
{
	uint8_t	ether_dhost[ETHER_ADDR_LEN];
	uint8_t	ether_shost[ETHER_ADDR_LEN];
	uint16_t	ether_type;
};

struct	ether_addr
{
	uint8_t octet[ETHER_ADDR_LEN];
};

#endif
