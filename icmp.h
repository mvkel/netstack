#ifndef ICMP_H
#define ICMP_H

#include "net_common.h"
#include "ipv4.h"

#define ICMP_HDR_LEN 8

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11

#define ICMP_CODE_TTL_EXCEEDED 0
#define ICMP_CODE_FRAG_TIME_EXCEEDED 1

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t check;
    uint16_t id;
    uint16_t seq;
} __attribute__((packed)) icmp_hdr_t;

int icmp_echo_request(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint16_t id, uint16_t seq, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int icmp_echo_reply(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint16_t id, uint16_t seq, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int icmp_time_exceeded(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint8_t code, const void *orig_packet, size_t orig_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int icmp_process(packet_t *pkt);
uint16_t icmp_checksum(const void *icmp_packet, size_t len);

#endif
