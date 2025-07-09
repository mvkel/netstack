#include "ethernet.h"
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

void eth_build_hdr(eth_hdr_t *hdr, const mac_addr_t *dst, const mac_addr_t *src, uint16_t ethertype) {
    memcpy(&hdr->dst, dst, ETH_ADDR_LEN);
    memcpy(&hdr->src, src, ETH_ADDR_LEN);
    hdr->ethertype = htons(ethertype);
}

int eth_send(int sockfd, const mac_addr_t *dst, const mac_addr_t *src, uint16_t ethertype, const void *payload, size_t payload_len) {
    uint8_t frame[MAX_PACKET_SIZE];
    eth_hdr_t *hdr = (eth_hdr_t *)frame;
    
    if (ETH_HDR_LEN + payload_len > MAX_PACKET_SIZE) {
        return -1;
    }
    
    eth_build_hdr(hdr, dst, src, ethertype);
    memcpy(frame + ETH_HDR_LEN, payload, payload_len);
    
    size_t frame_len = ETH_HDR_LEN + payload_len;
    if (frame_len < MIN_PACKET_SIZE) {
        memset(frame + frame_len, 0, MIN_PACKET_SIZE - frame_len);
        frame_len = MIN_PACKET_SIZE;
    }
    
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex("eth0");
    
    ssize_t sent = sendto(sockfd, frame, frame_len, 0, (struct sockaddr *)&sll, sizeof(sll));
    return (sent == (ssize_t)frame_len) ? 0 : -1;
}

int eth_recv(int sockfd, packet_t *pkt) {
    struct sockaddr_ll sll;
    socklen_t sll_len = sizeof(sll);
    
    ssize_t len = recvfrom(sockfd, pkt->data, MAX_PACKET_SIZE, 0, (struct sockaddr *)&sll, &sll_len);
    if (len < 0) {
        return -1;
    }
    
    pkt->len = len;
    pkt->sockfd = sockfd;
    return 0;
}

void eth_parse_hdr(const packet_t *pkt, eth_hdr_t *hdr) {
    memcpy(hdr, pkt->data, sizeof(eth_hdr_t));
    hdr->ethertype = ntohs(hdr->ethertype);
}
