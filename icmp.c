#include "icmp.h"

uint16_t icmp_checksum(const void *icmp_packet, size_t len) {
    return checksum(icmp_packet, len);
}

static int icmp_send(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint8_t type, uint8_t code, uint16_t id, uint16_t seq, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    uint8_t packet[MAX_PACKET_SIZE];
    icmp_hdr_t *hdr = (icmp_hdr_t *)packet;
    
    if (ICMP_HDR_LEN + data_len > MAX_PAYLOAD) {
        return -1;
    }
    
    hdr->type = type;
    hdr->code = code;
    hdr->check = 0;
    hdr->id = htons(id);
    hdr->seq = htons(seq);
    
    if (data && data_len > 0) {
        memcpy(packet + ICMP_HDR_LEN, data, data_len);
    }
    
    hdr->check = icmp_checksum(packet, ICMP_HDR_LEN + data_len);
    
    return ipv4_send(sockfd, src, dst, IPPROTO_ICMP, packet, ICMP_HDR_LEN + data_len, src_mac, dst_mac);
}

int icmp_echo_request(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint16_t id, uint16_t seq, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    return icmp_send(sockfd, src, dst, ICMP_TYPE_ECHO_REQUEST, 0, id, seq, data, data_len, src_mac, dst_mac);
}

int icmp_echo_reply(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint16_t id, uint16_t seq, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    return icmp_send(sockfd, src, dst, ICMP_TYPE_ECHO_REPLY, 0, id, seq, data, data_len, src_mac, dst_mac);
}

int icmp_time_exceeded(int sockfd, ipv4_addr_t src, ipv4_addr_t dst, uint8_t code, const void *orig_packet, size_t orig_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    uint8_t data[64];
    size_t copy_len = (orig_len > 64) ? 64 : orig_len;
    memcpy(data, orig_packet, copy_len);
    
    return icmp_send(sockfd, src, dst, ICMP_TYPE_TIME_EXCEEDED, code, 0, 0, data, copy_len, src_mac, dst_mac);
}

int icmp_process(packet_t *pkt) {
    ipv4_hdr_t ip;
    if (ipv4_parse_hdr(pkt, &ip) < 0) return -1;
    
    if (ip.protocol != IPPROTO_ICMP) return -1;
    
    size_t icmp_offset = ETH_HDR_LEN + IPV4_HDR_LEN;
    if (pkt->len < icmp_offset + ICMP_HDR_LEN) return -1;
    
    icmp_hdr_t *icmp = (icmp_hdr_t *)(pkt->data + icmp_offset);
    size_t icmp_len = pkt->len - icmp_offset;
    
    uint16_t check_orig = icmp->check;
    icmp->check = 0;
    uint16_t check_calc = icmp_checksum(icmp, icmp_len);
    icmp->check = check_orig;
    
    if (check_orig != check_calc) return -1;
    
    switch (icmp->type) {
        case ICMP_TYPE_ECHO_REQUEST:
            break;
        case ICMP_TYPE_ECHO_REPLY:
            break;
        case ICMP_TYPE_TIME_EXCEEDED:
            break;
        default:
            break;
    }
    
    return 0;
}
