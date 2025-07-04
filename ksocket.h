#ifndef SOCK_KTP
#define SOCK_KTP 3

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SOCK_KTP 3
#define MSG_SIZE 512
#define T 5
#define DROP_PROB 0.1

// Error codes
#define ENOSPACE 1001
#define ENOTBOUND 1002
#define ENOMESSAGE 1003

// Message types
#define DATA_MSG 1
#define ACK_MSG 2

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
    uint8_t next_seq_num;           
    int is_bound;
};

// Function declarations
int k_socket(int domain, int type, int protocol);
int k_bind(int sockfd, const char* src_ip, int src_port, const char* dest_ip, int dest_port);
int k_sendto(int sockfd, const void* buf, size_t len);
int k_recvfrom(int sockfd, void* buf, size_t len);
int k_close(int sockfd);

#endif