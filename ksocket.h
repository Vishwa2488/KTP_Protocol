/*
Assignment 3 Submission
Name: S Vishwa Gangadhar
Roll number: 22CS10061
Link of the pcap file: https://drive.google.com/drive/folders/1CTGuxU5v1IEo-f_8MRYhTjFstAqmpNf-?usp=drive_link
*/


#ifndef SOCK_KTP
#define SOCK_KTP 3

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h> 
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#define SOCK_KTP 3
#define MSG_SIZE 1024
#define T 200000
#define DROP_PROB 0.5

// Error codes
#define ENOSPACE 1001
#define ENOTBOUND 1002
#define ENOMESSAGE 1003

// Message types
#define DATA_MSG 1
#define ACK_MSG 2

// Shared memory key
#define SHM_KEY 1234

// max number of sockets
#define MAX_KTP_SOCKETS 10
#define MAX_SEQNUM 10

#define LEAVE printf("done\n");
#define ENTER printf("enter\n");

// KTP header structure
struct ktp_header {
    uint8_t seq_num;    // 8-bit sequence number
    uint8_t msg_type;   // DATA_MSG or ACK_MSG
};

// Structure to store socket information
struct ktp_sock_info {
    int udp_sock;
    struct sockaddr_in src_addr;
    struct sockaddr_in dest_addr;
    int next_seq_num;
    int is_use;       
    int is_bound;
    pid_t pid;
    int nospace;
    int pending;  // Number of messages waiting to be transmitted
    int expected_seq; // Receiver expects this sequence number next
    int last_ack;     // Last acknowledged sequence number

    // Sending data
    int swnd;                             // Number of unacknowledged messages currently in the window
    char send_buffer[MAX_SEQNUM][MSG_SIZE];
    struct timeval send_timestamps[MAX_SEQNUM];


    // Receiving data
    int rwnd;                       // Number of free slots in the receive buffer (initially MAX_SEQNUM)
    char rcv_buf[MAX_SEQNUM][MSG_SIZE];
  
    // Condition variable to wait for ACK reception for reliable send
    pthread_cond_t ack_cv;

    int total_transmissions; // Counts total packet transmissions (including retransmissions)
};

pthread_mutex_t lock; // lock for shared data

// Function declarations
int k_socket(int domain, int type, int protocol, const char* src_ip, int src_port, const char* dest_ip, int dest_port);
int k_bind(int sockfd, const char* src_ip, int src_port, const char* dest_ip, int dest_port);
int k_sendto(int sockfd, const void* buf, size_t len);
int k_recvfrom(int sockfd, void* buf, size_t len);
int k_close(int sockfd);
void print_ktp_sock(struct ktp_sock_info *sock);
int dropMessage(float p);

#endif