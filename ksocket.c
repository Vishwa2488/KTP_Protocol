/*
Assignment 3 Submission
Name: S Vishwa Gangadhar
Roll number: 22CS10061
Link of the pcap file: https://drive.google.com/drive/folders/1CTGuxU5v1IEo-f_8MRYhTjFstAqmpNf-?usp=drive_link
*/



#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/select.h>


struct ktp_sock_info * socks;  // Support up to 10 sockets for now


void print_ktp_sock(struct ktp_sock_info *sock) {
    if (sock == NULL) {
        printf("Invalid socket (NULL pointer)\n");
        return;
    }

    printf("===== KTP Socket Info =====\n");
    printf("UDP Socket FD   : %d\n", sock->udp_sock);
    
    // Print source address
    
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(sock->src_addr.sin_addr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(sock->dest_addr.sin_addr), dest_ip, INET_ADDRSTRLEN);

    printf("Source Address  : %s:%d\n", src_ip, ntohs(sock->src_addr.sin_port));
    printf("Destination Addr: %s:%d\n", dest_ip, ntohs(sock->dest_addr.sin_port));

    printf("Next Seq Number : %u\n", sock->next_seq_num);
    printf("In Use          : %s\n", sock->is_use ? "Yes" : "No");
    printf("Bound          : %s\n", sock->is_bound ? "Yes" : "No");
    printf("Pid            : %d\n", sock->pid);
    printf("==========================\n");
    return ;
}


// Drop message simulation
int dropMessage(float p) {
    float random = (float)rand() / RAND_MAX;
    return random < p;
}

int k_socket(int domain, int type, int protocol, const char* src_ip, int src_port, const char* dest_ip, int dest_port) {
    
    int shmid = shmget(SHM_KEY, MAX_KTP_SOCKETS * sizeof(struct ktp_sock_info), IPC_CREAT | 0666);
    if (shmid < 0) {
        perror("shmget failed");
        exit(1);
    }

    socks = (struct ktp_sock_info *)shmat(shmid, NULL, 0);

    if (socks == (void *)-1) {
        perror("shmat failed");
        exit(1);
    }

    if (type != SOCK_KTP) {
        return -1;
    }

    // Find free socket slot
    int sock_index = -1;
  
    pthread_mutex_lock(&lock);

    // First, check if a socket with matching src and dest already exists.
    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        if (!socks[i].is_use) {
            char curr_src_ip[INET_ADDRSTRLEN], curr_dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &socks[i].src_addr.sin_addr, curr_src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &socks[i].dest_addr.sin_addr, curr_dest_ip, INET_ADDRSTRLEN);
         
            if ((strcmp(curr_src_ip, src_ip) == 0) &&
                (socks[i].src_addr.sin_port == htons(src_port)) &&
                (strcmp(curr_dest_ip, dest_ip) == 0) &&
                (socks[i].dest_addr.sin_port == htons(dest_port))) {
                // Found an existing matching socket.
                sock_index = i;
                break;
            }
        }
    }

    if (sock_index == -1)
    {
        printf("No valid socket for requirement\n");
        pthread_mutex_unlock(&lock);
        return -1;
    }

    socks[sock_index].next_seq_num = 1;
    socks[sock_index].is_bound = 1;
    socks[sock_index].is_use = 1;
    socks[sock_index].expected_seq = 1;
    socks[sock_index].last_ack = 0;
    socks[sock_index].rwnd = MAX_SEQNUM;
    socks[sock_index].pid = getpid();
    socks[sock_index].total_transmissions = 0;
    pthread_mutex_unlock(&lock);

    return sock_index;  // Return KTP socket ID
}

int k_bind(int sockfd, const char* src_ip, int src_port, const char* dest_ip, int dest_port) {
   
    pthread_mutex_lock(&lock);
    if (sockfd < 0 || sockfd >= 10 || socks[sockfd].udp_sock == 0) {
        return -1;
    }

  
    char curr_src_ip[INET_ADDRSTRLEN], curr_dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &socks[sockfd].src_addr.sin_addr, curr_src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &socks[sockfd].dest_addr.sin_addr, curr_dest_ip, INET_ADDRSTRLEN);

    if (!((strcmp(curr_src_ip, src_ip) == 0) &&
        (socks[sockfd].src_addr.sin_port == htons(src_port)) &&
        (strcmp(curr_dest_ip, dest_ip) == 0) &&
        (socks[sockfd].dest_addr.sin_port == htons(dest_port)))) 
    {
        printf("Address not correct\n");
        pthread_mutex_unlock(&lock);
        return -1;
    }

    pthread_mutex_unlock(&lock);
    return 0;
}

int k_sendto(int sockfd, const void* buf, size_t len) {
    pthread_mutex_lock(&lock);

    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS || !socks[sockfd].is_bound) {
        pthread_mutex_unlock(&lock);
        errno = EBADF;
        return -1;
    }

    // Clip message length to MSG_SIZE.
    if (len > MSG_SIZE)
        len = MSG_SIZE;

    // Wait until there is space in the sending window.
    while (socks[sockfd].swnd >= MAX_SEQNUM) {
        pthread_cond_wait(&socks[sockfd].ack_cv, &lock);
    }

    // Compute circular buffer slot:
    int index = ((int)socks[sockfd].next_seq_num - 1) % MAX_SEQNUM;

    // Copy the data into the send buffer.
    memset(socks[sockfd].send_buffer[index], 0, MSG_SIZE);
    memcpy(socks[sockfd].send_buffer[index], buf, len);

    // Assign the sequence number for this message.
    uint8_t my_seq = socks[sockfd].next_seq_num;
    // Immediately send the packet.
    {
        char packet[MSG_SIZE + sizeof(struct ktp_header)];
        struct ktp_header hdr;
        hdr.seq_num = my_seq;
        hdr.msg_type = DATA_MSG;
        memcpy(packet, &hdr, sizeof(hdr));
        memcpy(packet + sizeof(hdr), socks[sockfd].send_buffer[index], MSG_SIZE);
        sendto(socks[sockfd].udp_sock, packet, MSG_SIZE + sizeof(hdr), 0,
               (struct sockaddr*)&socks[sockfd].dest_addr, sizeof(socks[sockfd].dest_addr));
        // Record the send timestamp.
        gettimeofday(&socks[sockfd].send_timestamps[index], NULL);
    }

    // Update for the next message.
    
    if (socks[sockfd].next_seq_num == 255) socks[sockfd].next_seq_num = (socks[sockfd].next_seq_num + 1) % MAX_SEQNUM;
    else socks[sockfd].next_seq_num = socks[sockfd].next_seq_num + 1;
    socks[sockfd].swnd++;  // One more outstanding packet.

    printf("k_sendto: Queued and sent message with seq %d in slot %d on socket %d\n",
           my_seq, index, sockfd);

    // Wait until a proper ACK is received (thread_R will update last_ack).
    while (socks[sockfd].last_ack < my_seq) {
        pthread_cond_wait(&socks[sockfd].ack_cv, &lock);
    }
    // At this point, thread_R has processed an ACK for my_seq and slid the window accordingly.
    pthread_mutex_unlock(&lock);
    return len;
}


int k_recvfrom(int sockfd, void* buf, size_t len) {
    pthread_mutex_lock(&lock);

    if (sockfd < 0 || sockfd >= MAX_KTP_SOCKETS || !socks[sockfd].is_bound) {
        pthread_mutex_unlock(&lock);
        errno = EBADF;
        return -1;
    }
    
    // Wait until there is at least one message in the receiver buffer.
    // The number of stored messages is: stored = MAX_SEQNUM - rwnd.
    while ((MAX_SEQNUM - socks[sockfd].rwnd) <= 0) {
        pthread_cond_wait(&socks[sockfd].ack_cv, &lock);
    }
    
    // At least one message is available.
    int count = MAX_SEQNUM - socks[sockfd].rwnd;
    int ret_bytes = MSG_SIZE; // Fixed-size message
    
    // Copy the first message from the rcv_buf to the user buffer.
    memcpy(buf, socks[sockfd].rcv_buf[0], (len < MSG_SIZE ? len : MSG_SIZE));
    
    // Shift remaining messages in the receive buffer to the left.
    for (int i = 1; i < count; i++) {
        memcpy(socks[sockfd].rcv_buf[i - 1], socks[sockfd].rcv_buf[i], MSG_SIZE);
    }
    // Clear the last slot.
    memset(socks[sockfd].rcv_buf[count - 1], 0, MSG_SIZE);
    
    // Increase rwnd by one to indicate one more free slot.
    socks[sockfd].rwnd++;
    
    pthread_mutex_unlock(&lock);
    return ret_bytes;
}


int k_close(int sockfd) {
    if (sockfd < 0 || sockfd >= 10 || socks[sockfd].udp_sock <= 0) {
        return -1;
    }

    close(socks[sockfd].udp_sock);
    memset(&socks[sockfd], 0, sizeof(struct ktp_sock_info));
    return 0;
}