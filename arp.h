#ifndef ARP_H
#define ARP_H

#include "net_common.h"
#include "ethernet.h"

#define ARP_HDR_LEN 28
#define ARP_CACHE_SIZE 256
#define ARP_CACHE_TIMEOUT 300

#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IPV4 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    mac_addr_t sha;
    ipv4_addr_t spa;
    mac_addr_t tha;
    ipv4_addr_t tpa;
} __attribute__((packed)) arp_hdr_t;

typedef struct arp_entry {
    ipv4_addr_t ip;
    mac_addr_t mac;
    time_t timestamp;
    struct arp_entry *next;
    struct arp_entry *prev;
} arp_entry_t;

typedef struct {
    arp_entry_t *entries[ARP_CACHE_SIZE];
    arp_entry_t *lru_head;
    arp_entry_t *lru_tail;
    size_t count;
} arp_cache_t;

void arp_init_cache(arp_cache_t *cache);
void arp_cache_add(arp_cache_t *cache, ipv4_addr_t ip, mac_addr_t mac);
arp_entry_t *arp_cache_lookup(arp_cache_t *cache, ipv4_addr_t ip);
void arp_cache_remove_lru(arp_cache_t *cache);

int arp_request(int sockfd, const mac_addr_t *src_mac, ipv4_addr_t src_ip, ipv4_addr_t dst_ip);
int arp_reply(int sockfd, const mac_addr_t *src_mac, ipv4_addr_t src_ip, const mac_addr_t *dst_mac, ipv4_addr_t dst_ip);
int arp_process(packet_t *pkt, arp_cache_t *cache);

#endif
