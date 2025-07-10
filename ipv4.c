#include "ipv4.h"

static uint16_t ip_id_counter = 0;

void ipv4_init_routing_table(routing_table_t *table) {
    memset(table, 0, sizeof(routing_table_t));
}

void ipv4_add_route(routing_table_t *table, ipv4_addr_t network, ipv4_addr_t netmask, ipv4_addr_t gateway, const char *iface, uint32_t metric) {
    if (table->count >= MAX_ROUTES) return;
    
    route_entry_t *entry = &table->routes[table->count];
    entry->network = network;
    entry->netmask = netmask;
    entry->gateway = gateway;
    strncpy(entry->iface, iface, sizeof(entry->iface) - 1);
    entry->metric = metric;
    table->count++;
}

route_entry_t *ipv4_find_route(routing_table_t *table, ipv4_addr_t dst) {
    route_entry_t *best = NULL;
    uint32_t longest_prefix = 0;
    
    for (size_t i = 0; i < table->count; i++) {
        route_entry_t *entry = &table->routes[i];
        if ((dst.addr & entry->netmask.addr) == entry->network.addr) {
            uint32_t prefix_len = __builtin_popcount(entry->netmask.addr);
            if (!best || prefix_len > longest_prefix) {
                best = entry;
                longest_prefix = prefix_len;
            }
        }
    }
    
    return best;
}

void ipv4_build_hdr(ipv4_hdr_t *hdr, ipv4_addr_t src, ipv4_addr_t dst, uint8_t protocol, uint16_t payload_len) {
    memset(hdr, 0, sizeof(ipv4_hdr_t));
    hdr->version_ihl = (IPV4_VERSION << 4) | 5;
    hdr->tos = 0;
    hdr->tot_len = htons(IPV4_HDR_LEN + payload_len);
    hdr->id = htons(ip_id_counter++);
    hdr->frag_off = htons(0x4000);
    hdr->ttl = IPV4_TTL_DEFAULT;
    hdr->protocol = protocol;
    hdr->saddr = src;
    hdr->daddr = dst;
    hdr->check = 0;
    hdr->check = ipv4_checksum(hdr);
}

uint16_t ipv4_checksum(const ipv4_hdr_t *hdr) {
    return checksum(hdr, IPV4_HDR_LEN);
}

int ipv4_send(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint8_t protocol, const void *payload, size_t payload_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    uint8_t packet[MAX_PACKET_SIZE];
    ipv4_hdr_t *hdr = (ipv4_hdr_t *)packet;
    
    if (IPV4_HDR_LEN + payload_len > MAX_PAYLOAD) {
        return -1;
    }
    
    ipv4_build_hdr(hdr, src, dst, protocol, payload_len);
    memcpy(packet + IPV4_HDR_LEN, payload, payload_len);
    
    return eth_send(sockfd, dst_mac, src_mac, ETHERTYPE_IPV4, packet, IPV4_HDR_LEN + payload_len);
}

int ipv4_parse_hdr(const packet_t *pkt, ipv4_hdr_t *hdr) {
    if (pkt->len < ETH_HDR_LEN + IPV4_HDR_LEN) return -1;
    
    memcpy(hdr, pkt->data + ETH_HDR_LEN, sizeof(ipv4_hdr_t));
    
    uint8_t version = (hdr->version_ihl >> 4) & 0xf;
    uint8_t ihl = hdr->version_ihl & 0xf;
    
    if (version != IPV4_VERSION || ihl < 5) return -1;
    
    hdr->tot_len = ntohs(hdr->tot_len);
    hdr->id = ntohs(hdr->id);
    hdr->frag_off = ntohs(hdr->frag_off);
    
    uint16_t calc_check = ipv4_checksum(hdr);
    if (calc_check != 0) return -1;
    
    return 0;
}

int ipv4_process(packet_t *pkt, routing_table_t *table) {
    eth_hdr_t eth;
    eth_parse_hdr(pkt, &eth);
    
    if (eth.ethertype != ETHERTYPE_IPV4) return -1;
    
    ipv4_hdr_t ip;
    if (ipv4_parse_hdr(pkt, &ip) < 0) return -1;
    
    if (ip.ttl <= 1) {
        return -1;
    }
    
    route_entry_t *route = ipv4_find_route(table, ip.daddr);
    if (!route) return -1;
    
    return 0;
}
