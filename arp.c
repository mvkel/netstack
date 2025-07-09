#include "arp.h"

void arp_init_cache(arp_cache_t *cache) {
    memset(cache, 0, sizeof(arp_cache_t));
}

static void arp_lru_move_to_head(arp_cache_t *cache, arp_entry_t *entry) {
    if (entry == cache->lru_head) return;
    
    if (entry->prev) entry->prev->next = entry->next;
    if (entry->next) entry->next->prev = entry->prev;
    
    if (entry == cache->lru_tail) cache->lru_tail = entry->prev;
    
    entry->prev = NULL;
    entry->next = cache->lru_head;
    if (cache->lru_head) cache->lru_head->prev = entry;
    cache->lru_head = entry;
    
    if (!cache->lru_tail) cache->lru_tail = entry;
}

void arp_cache_add(arp_cache_t *cache, ipv4_addr_t ip, mac_addr_t mac) {
    uint32_t hash = hash_ipv4(ip) % ARP_CACHE_SIZE;
    
    arp_entry_t *entry = cache->entries[hash];
    while (entry) {
        if (entry->ip.addr == ip.addr) {
            entry->mac = mac;
            entry->timestamp = time(NULL);
            arp_lru_move_to_head(cache, entry);
            return;
        }
        entry = entry->next;
    }
    
    if (cache->count >= ARP_CACHE_SIZE) {
        arp_cache_remove_lru(cache);
    }
    
    entry = malloc(sizeof(arp_entry_t));
    entry->ip = ip;
    entry->mac = mac;
    entry->timestamp = time(NULL);
    entry->next = cache->entries[hash];
    entry->prev = NULL;
    
    if (cache->entries[hash]) {
        cache->entries[hash]->prev = entry;
    }
    cache->entries[hash] = entry;
    
    arp_lru_move_to_head(cache, entry);
    cache->count++;
}

arp_entry_t *arp_cache_lookup(arp_cache_t *cache, ipv4_addr_t ip) {
    uint32_t hash = hash_ipv4(ip) % ARP_CACHE_SIZE;
    arp_entry_t *entry = cache->entries[hash];
    
    while (entry) {
        if (entry->ip.addr == ip.addr) {
            time_t now = time(NULL);
            if (now - entry->timestamp > ARP_CACHE_TIMEOUT) {
                return NULL;
            }
            arp_lru_move_to_head(cache, entry);
            return entry;
        }
        entry = entry->next;
    }
    
    return NULL;
}

void arp_cache_remove_lru(arp_cache_t *cache) {
    if (!cache->lru_tail) return;
    
    arp_entry_t *victim = cache->lru_tail;
    uint32_t hash = hash_ipv4(victim->ip) % ARP_CACHE_SIZE;
    
    if (victim->prev) victim->prev->next = victim->next;
    if (victim->next) victim->next->prev = victim->prev;
    
    if (cache->entries[hash] == victim) {
        cache->entries[hash] = victim->next;
    }
    
    if (victim == cache->lru_head) cache->lru_head = victim->next;
    if (victim == cache->lru_tail) cache->lru_tail = victim->prev;
    
    free(victim);
    cache->count--;
}

int arp_request(int sockfd, const mac_addr_t *src_mac, ipv4_addr_t src_ip, ipv4_addr_t dst_ip) {
    arp_hdr_t arp;
    mac_addr_t broadcast = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    mac_addr_t zero_mac = {{0}};
    
    arp.htype = htons(ARP_HTYPE_ETHERNET);
    arp.ptype = htons(ARP_PTYPE_IPV4);
    arp.hlen = ETH_ADDR_LEN;
    arp.plen = 4;
    arp.oper = htons(ARP_OP_REQUEST);
    arp.sha = *src_mac;
    arp.spa = src_ip;
    arp.tha = zero_mac;
    arp.tpa = dst_ip;
    
    return eth_send(sockfd, &broadcast, src_mac, ETHERTYPE_ARP, &arp, sizeof(arp));
}

int arp_reply(int sockfd, const mac_addr_t *src_mac, ipv4_addr_t src_ip, const mac_addr_t *dst_mac, ipv4_addr_t dst_ip) {
    arp_hdr_t arp;
    
    arp.htype = htons(ARP_HTYPE_ETHERNET);
    arp.ptype = htons(ARP_PTYPE_IPV4);
    arp.hlen = ETH_ADDR_LEN;
    arp.plen = 4;
    arp.oper = htons(ARP_OP_REPLY);
    arp.sha = *src_mac;
    arp.spa = src_ip;
    arp.tha = *dst_mac;
    arp.tpa = dst_ip;
    
    return eth_send(sockfd, dst_mac, src_mac, ETHERTYPE_ARP, &arp, sizeof(arp));
}

int arp_process(packet_t *pkt, arp_cache_t *cache) {
    if (pkt->len < ETH_HDR_LEN + ARP_HDR_LEN) return -1;
    
    eth_hdr_t eth;
    eth_parse_hdr(pkt, &eth);
    
    if (eth.ethertype != ETHERTYPE_ARP) return -1;
    
    arp_hdr_t *arp = (arp_hdr_t *)(pkt->data + ETH_HDR_LEN);
    
    if (ntohs(arp->htype) != ARP_HTYPE_ETHERNET || ntohs(arp->ptype) != ARP_PTYPE_IPV4) {
        return -1;
    }
    
    arp_cache_add(cache, arp->spa, arp->sha);
    
    return 0;
}
