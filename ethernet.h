#ifndef ETHERNET_H
#define ETHERNET_H

#include "net_common.h"

#define ETH_HDR_LEN 14
#define ETH_ADDR_LEN 6

typedef struct {
    mac_addr_t dst;
    mac_addr_t src;
    uint16_t ethertype;
} __attribute__((packed)) eth_hdr_t;

void eth_build_hdr(eth_hdr_t *hdr, const mac_addr_t *dst, const mac_addr_t *src, uint16_t ethertype);
int eth_send(int sockfd, const mac_addr_t *dst, const mac_addr_t *src, uint16_t ethertype, const void *payload, size_t payload_len);
int eth_recv(int sockfd, packet_t *pkt);
void eth_parse_hdr(const packet_t *pkt, eth_hdr_t *hdr);

#endif
