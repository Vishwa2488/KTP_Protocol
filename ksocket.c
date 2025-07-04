#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>

static struct ktp_sock_info socks[10];  // Support up to 10 sockets for now

// Drop message simulation
int dropMessage(float p) {
    float random = (float)rand() / RAND_MAX;
    return random < p;
}

int k_socket(int domain, int type, int protocol) {
    if (type != SOCK_KTP) {
        return -1;
    }

    // Find free socket slot
    int i;
    for (i = 0; i < 10; i++) {
        if (socks[i].udp_sock == 0) {
            break;
        }
    }

    if (i == 10) {
        return -1;
    }

    // Create UDP socket
    int udp_sock = socket(domain, SOCK_DGRAM, protocol);
    if (udp_sock < 0) {
        return -1;
    }

    socks[i].udp_sock = udp_sock;
    socks[i].next_seq_num = 1;
    socks[i].is_bound = 0;

    return i;  // Return KTP socket ID
}

int k_bind(int sockfd, const char* src_ip, int src_port, const char* dest_ip, int dest_port) {
    if (sockfd < 0 || sockfd >= 10 || socks[sockfd].udp_sock == 0) {
        return -1;
    }

    // Set up source address
    memset(&socks[sockfd].src_addr, 0, sizeof(struct sockaddr_in));
    socks[sockfd].src_addr.sin_family = AF_INET;
    socks[sockfd].src_addr.sin_port = htons(src_port);
    inet_pton(AF_INET, src_ip, &socks[sockfd].src_addr.sin_addr);

    // Set up destination address
    memset(&socks[sockfd].dest_addr, 0, sizeof(struct sockaddr_in));
    socks[sockfd].dest_addr.sin_family = AF_INET;
    socks[sockfd].dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &socks[sockfd].dest_addr.sin_addr);

    // Bind UDP socket
    if (bind(socks[sockfd].udp_sock, (struct sockaddr*)&socks[sockfd].src_addr, 
             sizeof(struct sockaddr_in)) < 0) {
        return -1;
    }

    socks[sockfd].is_bound = 1;
    return 0;
}

int k_sendto(int sockfd, const void* buf, size_t len) {
    if (sockfd < 0 || sockfd >= 10 || !socks[sockfd].is_bound) {
        return -1;
    }

    // Prepare message with header
    char msg[MSG_SIZE + sizeof(struct ktp_header)];
    struct ktp_header* hdr = (struct ktp_header*)msg;
    hdr->seq_num = socks[sockfd].next_seq_num;
    printf("socks[sockfd].next_seq_num = %d\n", socks[sockfd].next_seq_num);
    hdr->msg_type = DATA_MSG;
    
    // Copy data after header
    memcpy(msg + sizeof(struct ktp_header), buf, len);

    // Send message and wait for ACK
    while (1) {
        // Send message
        printf("Sender: Sending packet for Sequence number: %d\n", hdr->seq_num);
        sendto(socks[sockfd].udp_sock, msg, len + sizeof(struct ktp_header), 0,
               (struct sockaddr*)&socks[sockfd].dest_addr, sizeof(struct sockaddr_in));

        // Wait for ACK with timeout
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(socks[sockfd].udp_sock, &readfds);
        tv.tv_sec = T;
        tv.tv_usec = 0;
        
        // used select to have a timeout
        if (select(socks[sockfd].udp_sock + 1, &readfds, NULL, NULL, &tv) > 0) {
            char ack_msg[sizeof(struct ktp_header)];
            struct sockaddr_in from_addr;
            socklen_t from_len = sizeof(from_addr);
            
            recvfrom(socks[sockfd].udp_sock, ack_msg, sizeof(struct ktp_header), 0,
                    (struct sockaddr*)&from_addr, &from_len);

            struct ktp_header* ack_hdr = (struct ktp_header*)ack_msg;
            if (ack_hdr->msg_type == ACK_MSG && ack_hdr->seq_num == hdr->seq_num) {
                
                // ACK received successfully
                printf("Sender: Got ACK for sequence number: %d\n", ack_hdr->seq_num);
                socks[sockfd].next_seq_num++;
                return len;
            }
            else
            {
                printf("Not ACK\n");
                return -1;
            }
        }
        // Timeout occurred, retry
        printf("Timeout occurred, retrying...\n");
    }

    printf("Max retries exceeded\n");

    return -1;  // Max retries exceeded
}

int k_recvfrom(int sockfd, void* buf, size_t len) {
    
    if (sockfd < 0 || sockfd >= 10 || !socks[sockfd].is_bound) {
        return -1;
    }
    
    char msg[MSG_SIZE + sizeof(struct ktp_header)];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    // Receive message
    int recv_len = recvfrom(socks[sockfd].udp_sock, msg, len + sizeof(struct ktp_header), 0,
                           (struct sockaddr*)&from_addr, &from_len);

    if (recv_len <= 0) {
        return 0;
    }

    struct ktp_header* hdr = (struct ktp_header*)msg;

    // Simulate packet loss
    if (dropMessage(DROP_PROB)) {
        printf("Reciver: Message dropped for sequence number: %d\n", hdr->seq_num);
        return -1;
    }

    // Send ACK
    struct ktp_header ack_hdr;
    ack_hdr.seq_num = hdr->seq_num;
    ack_hdr.msg_type = ACK_MSG;
    
    printf("Receiver: Received message with sequence number: %d\n", hdr->seq_num);
    sendto(socks[sockfd].udp_sock, &ack_hdr, sizeof(ack_hdr), 0,
           (struct sockaddr*)&from_addr, from_len);

    printf("Receiver: Sent ACK for sequence number: %d\n", ack_hdr.seq_num);
    // Copy received data to user buffer
    memcpy(buf, msg + sizeof(struct ktp_header), recv_len - sizeof(struct ktp_header));
    return recv_len - sizeof(struct ktp_header);
}

int k_close(int sockfd) {
    if (sockfd < 0 || sockfd >= 10 || socks[sockfd].udp_sock <= 0) {
        return -1;
    }

    close(socks[sockfd].udp_sock);
    memset(&socks[sockfd], 0, sizeof(struct ktp_sock_info));
    return 0;
}