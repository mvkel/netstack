#ifndef TFTP_H
#define TFTP_H

#include "net_common.h"
#include "udp.h"

#define TFTP_PORT 69
#define TFTP_DATA_SIZE 512
#define TFTP_MAX_RETRIES 5
#define TFTP_TIMEOUT 5

#define TFTP_OP_RRQ 1
#define TFTP_OP_WRQ 2
#define TFTP_OP_DATA 3
#define TFTP_OP_ACK 4
#define TFTP_OP_ERROR 5

#define TFTP_ERR_NOT_DEFINED 0
#define TFTP_ERR_FILE_NOT_FOUND 1
#define TFTP_ERR_ACCESS_VIOLATION 2
#define TFTP_ERR_DISK_FULL 3
#define TFTP_ERR_ILLEGAL_OP 4
#define TFTP_ERR_UNKNOWN_TID 5
#define TFTP_ERR_FILE_EXISTS 6
#define TFTP_ERR_NO_SUCH_USER 7

typedef struct {
    uint16_t opcode;
    union {
        struct {
            char filename_mode[1];
        } request;
        struct {
            uint16_t block;
            uint8_t data[TFTP_DATA_SIZE];
        } data;
        struct {
            uint16_t block;
        } ack;
        struct {
            uint16_t error_code;
            char error_msg[1];
        } error;
    } u;
} __attribute__((packed)) tftp_packet_t;

typedef enum {
    TFTP_STATE_IDLE,
    TFTP_STATE_READING,
    TFTP_STATE_WRITING,
    TFTP_STATE_DONE,
    TFTP_STATE_ERROR
} tftp_state_t;

typedef struct {
    tftp_state_t state;
    ipv4_addr_t peer_ip;
    uint16_t peer_port;
    uint16_t local_port;
    uint16_t block_num;
    FILE *file;
    char filename[256];
    int retries;
    time_t last_packet_time;
} tftp_session_t;

int tftp_send_rrq(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, const char *filename, const char *mode, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int tftp_send_wrq(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, const char *filename, const char *mode, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int tftp_send_data(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t block, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int tftp_send_ack(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t block, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);
int tftp_send_error(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t error_code, const char *error_msg, const mac_addr_t *src_mac, const mac_addr_t *dst_mac);

void tftp_handler(const packet_t *pkt, const udp_hdr_t *udp, const void *data, size_t len);
void tftp_process_session(tftp_session_t *session, const tftp_packet_t *tftp, size_t len);

#endif
