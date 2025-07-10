#ifndef IPV4_H
#define IPV4_H

#include "net_common.h"
#include "ethernet.h"

#define IPV4_HDR_LEN 20
#define IPV4_VERSION 4
#define IPV4_TTL_DEFAULT 64

#define MAX_ROUTES 256

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    ipv4_addr_t saddr;
    ipv4_addr_t daddr;
} __attribute__((packed)) ipv4_hdr_t;

typedef struct {
    ipv4_addr_t network;
    ipv4_addr_t netmask;
    ipv4_addr_t gateway;
    char iface[16];
    uint32_t metric;
} route_entry_t;

typedef struct {
    route_entry_t routes[MAX_ROUTES];
    size_t count;
} routing_table_t;

void ipv4_init_routing_table(routing_table_t *table);
void ipv4_add_route(routing_table_t *table, ipv4_addr_t network, ipv4_addr_t netmask, ipv4_addr_t gateway, const char *iface, uint32_t metric);
route_entry_t *ipv4_find_route(routing_table_t *table, ipv4_addr_t dst);

void ipv4_build_hdr(ipv4_hdr_t *hdr, ipv4_addr_t src, ipv4_addr_t dst, uint8_t protocol, uint16_t payload_len);
uint16_t ipv4_checksum(const ipv4_hdr_t *hdr);
int ipv4_send(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint8_t protocol, const void *payload, size_t payload_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int ipv4_parse_hdr(const packet_t *pkt, ipv4_hdr_t *hdr);
int ipv4_process(packet_t *pkt, routing_table_t *table);

#endif
