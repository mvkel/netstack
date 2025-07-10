#include "udp.h"

void udp_init_port_table(udp_port_table_t *table) {
    memset(table, 0, sizeof(udp_port_table_t));
}

int udp_bind_port(udp_port_table_t *table, uint16_t port, void (*handler)(const packet_t *, const udp_hdr_t *, const void *, size_t)) {
    if (table->count >= MAX_UDP_PORTS) return -1;
    
    for (size_t i = 0; i < table->count; i++) {
        if (table->bindings[i].port == port) {
            return -1;
        }
    }
    
    table->bindings[table->count].port = port;
    table->bindings[table->count].handler = handler;
    table->count++;
    
    return 0;
}

void udp_unbind_port(udp_port_table_t *table, uint16_t port) {
    for (size_t i = 0; i < table->count; i++) {
        if (table->bindings[i].port == port) {
            memmove(&table->bindings[i], &table->bindings[i + 1], 
                    (table->count - i - 1) * sizeof(udp_port_binding_t));
            table->count--;
            return;
        }
    }
}

uint16_t udp_checksum(ipv4_addr_t src, ipv4_addr_t dst, const udp_hdr_t *udp, const void *data, size_t data_len) {
    struct {
        ipv4_addr_t src;
        ipv4_addr_t dst;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_len;
    } __attribute__((packed)) pseudo_hdr;
    
    pseudo_hdr.src = src;
    pseudo_hdr.dst = dst;
    pseudo_hdr.zero = 0;
    pseudo_hdr.protocol = IPPROTO_UDP;
    pseudo_hdr.udp_len = htons(UDP_HDR_LEN + data_len);
    
    size_t total_len = sizeof(pseudo_hdr) + UDP_HDR_LEN + data_len;
    uint8_t *buffer = malloc(total_len);
    
    memcpy(buffer, &pseudo_hdr, sizeof(pseudo_hdr));
    memcpy(buffer + sizeof(pseudo_hdr), udp, UDP_HDR_LEN);
    if (data && data_len > 0) {
        memcpy(buffer + sizeof(pseudo_hdr) + UDP_HDR_LEN, data, data_len);
    }
    
    uint16_t check = checksum(buffer, total_len);
    free(buffer);
    
    return check;
}

int udp_send(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    uint8_t packet[MAX_PACKET_SIZE];
    udp_hdr_t *udp = (udp_hdr_t *)packet;
    
    if (UDP_HDR_LEN + data_len > MAX_PAYLOAD) {
        return -1;
    }
    
    udp->sport = htons(src_port);
    udp->dport = htons(dst_port);
    udp->len = htons(UDP_HDR_LEN + data_len);
    udp->check = 0;
    
    if (data && data_len > 0) {
        memcpy(packet + UDP_HDR_LEN, data, data_len);
    }
    
    udp->check = udp_checksum(src_ip, dst_ip, udp, data, data_len);
    
    return ipv4_send(sockfd, src_ip, dst_ip, IPPROTO_UDP, packet, UDP_HDR_LEN + data_len, src_mac, dst_mac);
}

int udp_process(packet_t *pkt, udp_port_table_t *table) {
    ipv4_hdr_t ip;
    if (ipv4_parse_hdr(pkt, &ip) < 0) return -1;
    
    if (ip.protocol != IPPROTO_UDP) return -1;
    
    size_t udp_offset = ETH_HDR_LEN + IPV4_HDR_LEN;
    if (pkt->len < udp_offset + UDP_HDR_LEN) return -1;
    
    udp_hdr_t *udp = (udp_hdr_t *)(pkt->data + udp_offset);
    uint16_t udp_len = ntohs(udp->len);
    
    if (pkt->len < udp_offset + udp_len) return -1;
    
    uint16_t dport = ntohs(udp->dport);
    
    for (size_t i = 0; i < table->count; i++) {
        if (table->bindings[i].port == dport) {
            void *data = (udp_len > UDP_HDR_LEN) ? (pkt->data + udp_offset + UDP_HDR_LEN) : NULL;
            size_t data_len = udp_len - UDP_HDR_LEN;
            table->bindings[i].handler(pkt, udp, data, data_len);
            return 0;
        }
    }
    
    return -1;
}
