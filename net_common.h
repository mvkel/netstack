#ifndef NET_COMMON_H
#define NET_COMMON_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#define MAX_PACKET_SIZE 1518
#define MIN_PACKET_SIZE 64
#define MAX_PAYLOAD 1500

#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD

#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

typedef struct {
    uint8_t data[MAX_PACKET_SIZE];
    size_t len;
    int sockfd;
    struct sockaddr_in addr;
} packet_t;

typedef struct {
    uint8_t addr[6];
} mac_addr_t;

typedef struct {
    uint32_t addr;
} ipv4_addr_t;

uint16_t checksum(const void *data, size_t len);
void print_hex(const uint8_t *data, size_t len);
int create_raw_socket(void);
uint32_t hash_ipv4(ipv4_addr_t ip);

#endif
