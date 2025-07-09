#include "net_common.h"
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

uint16_t checksum(const void *data, size_t len) {
    const uint16_t *words = data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *words++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t*)words;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    return ~sum;
}

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

int create_raw_socket(void) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    return sockfd;
}

uint32_t hash_ipv4(ipv4_addr_t ip) {
    uint32_t hash = ip.addr;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    return hash;
}
