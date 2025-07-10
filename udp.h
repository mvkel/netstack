#ifndef UDP_H
#define UDP_H

#include "net_common.h"
#include "ipv4.h"

#define UDP_HDR_LEN 8
#define MAX_UDP_PORTS 1024

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t check;
} __attribute__((packed)) udp_hdr_t;

typedef struct {
    uint16_t port;
    void (*handler)(const packet_t *pkt, const udp_hdr_t *udp, const void *data, size_t len);
} udp_port_binding_t;

typedef struct {
    udp_port_binding_t bindings[MAX_UDP_PORTS];
    size_t count;
} udp_port_table_t;

void udp_init_port_table(udp_port_table_t *table);
int udp_bind_port(udp_port_table_t *table, uint16_t port, void (*handler)(const packet_t *, const udp_hdr_t *, const void *, size_t));
void udp_unbind_port(udp_port_table_t *table, uint16_t port);

int udp_send(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int udp_process(packet_t *pkt, udp_port_table_t *table);
uint16_t udp_checksum(ipv4_addr_t src, ipv4_addr_t dst, const udp_hdr_t *udp, const void *data, size_t data_len);

#endif
