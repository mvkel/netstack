#include "tftp.h"

static tftp_session_t sessions[16];
static size_t num_sessions = 0;

static int tftp_send_packet(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, const void *packet, size_t len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    return udp_send(sockfd, src_ip, dst_ip, src_port, dst_port, packet, len, src_mac, dst_mac);
}

int tftp_send_rrq(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, const char *filename, const char *mode, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    uint8_t packet[512];
    tftp_packet_t *tftp = (tftp_packet_t *)packet;
    
    tftp->opcode = htons(TFTP_OP_RRQ);
    
    size_t offset = 2;
    size_t filename_len = strlen(filename);
    memcpy(packet + offset, filename, filename_len);
    offset += filename_len;
    packet[offset++] = 0;
    
    size_t mode_len = strlen(mode);
    memcpy(packet + offset, mode, mode_len);
    offset += mode_len;
    packet[offset++] = 0;
    
    return tftp_send_packet(sockfd, src_ip, dst_ip, 0, TFTP_PORT, packet, offset, src_mac, dst_mac);
}

int tftp_send_wrq(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, const char *filename, const char *mode, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    uint8_t packet[512];
    tftp_packet_t *tftp = (tftp_packet_t *)packet;
    
    tftp->opcode = htons(TFTP_OP_WRQ);
    
    size_t offset = 2;
    size_t filename_len = strlen(filename);
    memcpy(packet + offset, filename, filename_len);
    offset += filename_len;
    packet[offset++] = 0;
    
    size_t mode_len = strlen(mode);
    memcpy(packet + offset, mode, mode_len);
    offset += mode_len;
    packet[offset++] = 0;
    
    return tftp_send_packet(sockfd, src_ip, dst_ip, 0, TFTP_PORT, packet, offset, src_mac, dst_mac);
}

int tftp_send_data(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t block, const void *data, size_t data_len, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    uint8_t packet[516];
    tftp_packet_t *tftp = (tftp_packet_t *)packet;
    
    if (data_len > TFTP_DATA_SIZE) return -1;
    
    tftp->opcode = htons(TFTP_OP_DATA);
    tftp->u.data.block = htons(block);
    
    if (data && data_len > 0) {
        memcpy(tftp->u.data.data, data, data_len);
    }
    
    return tftp_send_packet(sockfd, src_ip, dst_ip, src_port, dst_port, packet, 4 + data_len, src_mac, dst_mac);
}

int tftp_send_ack(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t block, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    tftp_packet_t tftp;
    
    tftp.opcode = htons(TFTP_OP_ACK);
    tftp.u.ack.block = htons(block);
    
    return tftp_send_packet(sockfd, src_ip, dst_ip, src_port, dst_port, &tftp, 4, src_mac, dst_mac);
}

int tftp_send_error(int sockfd, ipv4_addr_t src_ip, ipv4_addr_t dst_ip, uint16_t src_port, uint16_t dst_port, uint16_t error_code, const char *error_msg, const mac_addr_t *src_mac, const mac_addr_t *dst_mac) {
    uint8_t packet[512];
    tftp_packet_t *tftp = (tftp_packet_t *)packet;
    
    tftp->opcode = htons(TFTP_OP_ERROR);
    tftp->u.error.error_code = htons(error_code);
    
    size_t msg_len = strlen(error_msg);
    memcpy(packet + 4, error_msg, msg_len);
    packet[4 + msg_len] = 0;
    
    return tftp_send_packet(sockfd, src_ip, dst_ip, src_port, dst_port, packet, 5 + msg_len, src_mac, dst_mac);
}

void tftp_handler(const packet_t *pkt, const udp_hdr_t *udp, const void *data, size_t len) {
    if (len < 2) return;
    
    tftp_packet_t *tftp = (tftp_packet_t *)data;
    uint16_t opcode = ntohs(tftp->opcode);
    
    ipv4_hdr_t ip;
    ipv4_parse_hdr(pkt, &ip);
    
    uint16_t src_port = ntohs(udp->sport);
    
    tftp_session_t *session = NULL;
    for (size_t i = 0; i < num_sessions; i++) {
        if (sessions[i].peer_ip.addr == ip.saddr.addr && sessions[i].peer_port == src_port) {
            session = &sessions[i];
            break;
        }
    }
    
    if (!session && num_sessions < 16) {
        session = &sessions[num_sessions++];
        memset(session, 0, sizeof(tftp_session_t));
        session->peer_ip = ip.saddr;
        session->peer_port = src_port;
        session->state = TFTP_STATE_IDLE;
    }
    
    if (session) {
        tftp_process_session(session, tftp, len);
    }
}

void tftp_process_session(tftp_session_t *session, const tftp_packet_t *tftp, size_t len) {
    uint16_t opcode = ntohs(tftp->opcode);
    
    switch (opcode) {
        case TFTP_OP_RRQ:
        case TFTP_OP_WRQ: {
            char *filename = (char *)&tftp->u.request.filename_mode;
            char *mode = filename + strlen(filename) + 1;
            
            strncpy(session->filename, filename, sizeof(session->filename) - 1);
            
            if (opcode == TFTP_OP_RRQ) {
                session->file = fopen(session->filename, "rb");
                session->state = TFTP_STATE_READING;
            } else {
                session->file = fopen(session->filename, "wb");
                session->state = TFTP_STATE_WRITING;
            }
            
            session->block_num = (opcode == TFTP_OP_RRQ) ? 1 : 0;
            session->last_packet_time = time(NULL);
            break;
        }
        
        case TFTP_OP_DATA: {
            if (session->state != TFTP_STATE_WRITING) break;
            
            uint16_t block = ntohs(tftp->u.data.block);
            size_t data_len = len - 4;
            
            if (block == session->block_num + 1) {
                if (session->file) {
                    fwrite(tftp->u.data.data, 1, data_len, session->file);
                }
                session->block_num = block;
                
                if (data_len < TFTP_DATA_SIZE) {
                    session->state = TFTP_STATE_DONE;
                    if (session->file) {
                        fclose(session->file);
                        session->file = NULL;
                    }
                }
            }
            break;
        }
        
        case TFTP_OP_ACK: {
            if (session->state != TFTP_STATE_READING) break;
            
            uint16_t block = ntohs(tftp->u.ack.block);
            
            if (block == session->block_num) {
                session->block_num++;
                session->retries = 0;
            }
            break;
        }
        
        case TFTP_OP_ERROR: {
            session->state = TFTP_STATE_ERROR;
            if (session->file) {
                fclose(session->file);
                session->file = NULL;
            }
            break;
        }
    }
}
