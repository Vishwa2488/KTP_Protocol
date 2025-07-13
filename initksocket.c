/*
Assignment 3 Submission
Name: S Vishwa Gangadhar
Roll number: 22CS10061
Link of the pcap file: https://drive.google.com/drive/folders/1CTGuxU5v1IEo-f_8MRYhTjFstAqmpNf-?usp=drive_link
*/


#include "ksocket.h"

struct ktp_sock_info * socks; 

// Signal handler to cleanup UDP sockets and detach shared memory
void cleanup_handler(int sig) {
    printf("\nReceived signal %d. Cleaning up UDP sockets...\n", sig);
    pthread_mutex_unlock(&lock);
    // Lock the global mutex to safely access shared memory
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        if (socks[i].udp_sock > 0) {
            close(socks[i].udp_sock);
            socks[i].udp_sock = 0;
        }
    }
    // printf("Total transmissions of socket 0: %d\n", socks[0].total_transmissions);
    pthread_mutex_unlock(&lock);
    
    // Detach the shared memory segment
    shmdt(socks);
    
    printf("\n\nCleanup complete. Exiting now.\n");


    exit(0);
}

void* thread_R(void *arg) {
    fd_set readfds;
    struct timeval tv;
    int max_fd;

    while (1) {
        FD_ZERO(&readfds);
        pthread_mutex_lock(&lock);
        max_fd = 0;
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            if (socks[i].is_use && socks[i].is_bound) {
                FD_SET(socks[i].udp_sock, &readfds);
                if (socks[i].udp_sock > max_fd)
                    max_fd = socks[i].udp_sock;
            }
        }
        pthread_mutex_unlock(&lock);

        tv.tv_sec = 0;
        tv.tv_usec = T;
        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            perror("select error in thread R");
            continue;
        } else if (ret == 0) {
            // Timeout: if needed, send duplicate ACKs.
            pthread_mutex_lock(&lock);
            for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
                if (socks[i].is_use && socks[i].is_bound && socks[i].nospace && (socks[i].rwnd > 0)) {
                    struct ktp_header dup_ack;
                    dup_ack.seq_num = socks[i].last_ack;
                    dup_ack.msg_type = ACK_MSG;
                    printf("Thread R: (Timeout) Sending duplicate ACK on socket %d for seq %d, rwnd=%d\n",
                           i, dup_ack.seq_num, socks[i].rwnd);
                    sendto(socks[i].udp_sock, &dup_ack, sizeof(dup_ack), 0,
                           (struct sockaddr*)&socks[i].dest_addr, sizeof(socks[i].dest_addr));
                    socks[i].nospace = 0;
                }
            }
            pthread_mutex_unlock(&lock);
            continue;
        }

        pthread_mutex_lock(&lock);
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            if (socks[i].is_use && socks[i].is_bound && FD_ISSET(socks[i].udp_sock, &readfds)) {
                char buffer[MSG_SIZE + sizeof(struct ktp_header)];
                struct sockaddr_in src_addr;
                socklen_t addr_len = sizeof(src_addr);
                int bytes = recvfrom(socks[i].udp_sock, buffer, sizeof(buffer), 0,
                                      (struct sockaddr *)&src_addr, &addr_len);
                if (bytes <= 0)
                    continue;

                struct ktp_header *hdr = (struct ktp_header *)buffer;

                
                if (hdr->msg_type == DATA_MSG) {
                    // If the data is in order:
                    if (hdr->seq_num == socks[i].expected_seq) {
                        
                        // Simulate loss
                        if (dropMessage(DROP_PROB))
                        {
                            printf("Thread R: Received DATA on socket %d dropped, seq=%d\n", i, hdr->seq_num);
                            continue;
                        }
                        else printf("Thread R: Received DATA on socket %d, seq=%d\n", i, hdr->seq_num);
                        
                    
                        
                        socks[i].expected_seq++;
                        socks[i].last_ack = hdr->seq_num;

                        // Calculate how many messages are already stored.
                        // (Number stored = MAX_SEQNUM - rwnd)
                        int count = MAX_SEQNUM - socks[i].rwnd;
                        
                        // Store the payload (data after the header) into the receiver buffer.
                        memcpy(socks[i].rcv_buf[count], buffer + sizeof(struct ktp_header), MSG_SIZE);
        
                        

                        if (socks[i].rwnd > 0)
                            socks[i].rwnd--;
                        // Send ACK.
                        struct ktp_header ack;
                        ack.seq_num = hdr->seq_num;
                        ack.msg_type = ACK_MSG;
                        printf("Thread R: Sending ACK on socket %d for seq=%d, rwnd=%d\n",
                               i, ack.seq_num, socks[i].rwnd);
                
                        sendto(socks[i].udp_sock, &ack, sizeof(ack), 0,
                               (struct sockaddr*)&socks[i].dest_addr, sizeof(socks[i].dest_addr));
                        pthread_cond_signal(&socks[i].ack_cv);
                    } else {
                        printf("Thread R: Out-of-order DATA on socket %d: received seq=%d, expected=%d\n",
                               i, hdr->seq_num, socks[i].expected_seq);
                    }
                } else if (hdr->msg_type == ACK_MSG) {
                    if (hdr->seq_num > socks[i].last_ack) {
                        int acked = hdr->seq_num - socks[i].last_ack;
                        socks[i].last_ack = hdr->seq_num;
                        if (socks[i].swnd >= acked)
                            socks[i].swnd -= acked;
                        printf("Thread R: Processed ACK on socket %d for seq=%d, swnd=%d\n",
                               i, hdr->seq_num, socks[i].swnd);
                        pthread_cond_signal(&socks[i].ack_cv);
                    }
                }
            }
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

void* thread_S(void *arg) {
    while (1) {
        usleep(T/2);
        pthread_mutex_lock(&lock);
        for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
            if (!socks[i].is_use || !socks[i].is_bound)
                continue;

            struct ktp_sock_info *sock = &socks[i];
            struct timeval curr_time;
            gettimeofday(&curr_time, NULL);

            // For each outstanding packet (from last_ack+1 to last_ack+swnd)
            for (int j = 0; j < sock->swnd; j++) {
                uint8_t seq = sock->last_ack + j + 1;
                int index = ((int)seq - 1) % MAX_SEQNUM;
                long elapsed_time = (curr_time.tv_sec - sock->send_timestamps[index].tv_sec) * 1000000L +
                    (curr_time.tv_usec - sock->send_timestamps[index].tv_usec);
;
                if (elapsed_time >= T) {
                    char packet[MSG_SIZE + sizeof(struct ktp_header)];
                    struct ktp_header hdr;
                    hdr.seq_num = seq;
                    hdr.msg_type = DATA_MSG;
                    memcpy(packet, &hdr, sizeof(hdr));
                    memcpy(packet + sizeof(hdr), sock->send_buffer[index], MSG_SIZE);
                    printf("Thread S: Retransmitting packet with seq %d for socket %d\n", seq, i);
                    sendto(sock->udp_sock, packet, MSG_SIZE + sizeof(hdr), 0,
                           (struct sockaddr*)&sock->dest_addr, sizeof(sock->dest_addr));
                    // Increment the transmission count
                    socks[i].total_transmissions++;
                    printf("Thread S: Total transmissions of socket %d: %d\n", i, socks[i].total_transmissions);
                    // Update the send timestamp for this slot.
                    gettimeofday(&sock->send_timestamps[index], NULL);
                }
            }
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}


void start_garbage_collector()
{
    while (1)
    {
        pthread_mutex_lock(&lock);
        for (int i=0;i<MAX_KTP_SOCKETS;i++)
        {
            if (socks[i].is_bound && kill(socks[i].pid, 0) != 0)
            {
                memset(&socks[i], 0, sizeof(struct ktp_sock_info)); 
            }
        }
       
        pthread_mutex_unlock(&lock);
   
    }

    return ;
}

int main() {

    // Register the cleanup signal handler for SIGINT and SIGTERM
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);


    if (pthread_mutex_init(&lock, NULL) != 0) { 
        printf("\n mutex init has failed\n"); 
        return 1; 
    }

    int shmid = shmget(SHM_KEY, MAX_KTP_SOCKETS * sizeof(struct ktp_sock_info), IPC_CREAT | 0666);
    if (shmid < 0) {
        perror("shmget failed");
        exit(1);
    }
    
  
    pthread_mutex_lock(&lock);
    socks = (struct ktp_sock_info *)shmat(shmid, NULL, 0);

    if (socks == (void *)-1) {
        perror("shmat failed");
        exit(1);
    }
    // Initialize shared memory
    memset(socks, 0, MAX_KTP_SOCKETS * sizeof(struct ktp_sock_info));
    
    for (int i = 0; i < MAX_KTP_SOCKETS; i++) {
        pthread_cond_init(&socks[i].ack_cv, NULL);
    }
    for (int i=0;i<MAX_KTP_SOCKETS;i++)
    {
        socks[i].udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (socks[i].udp_sock < 0)
        {
            printf("socks[%d].udp_sock = %d\n", i, socks[i].udp_sock);
        }
    }

    // Bind each UDP socket to a default address (e.g., 127.0.0.1) and a unique port.
    struct sockaddr_in default_addr;
    memset(&default_addr, 0, sizeof(default_addr));
    default_addr.sin_family = AF_INET;
    default_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    default_addr.sin_port = htons(8000);
    socks[0].src_addr = default_addr;

    socks[1].dest_addr = default_addr;

    default_addr.sin_port = htons(8001);
    socks[0].dest_addr = default_addr;
    socks[1].src_addr = default_addr;

    if (bind(socks[0].udp_sock, (struct sockaddr *)&socks[0].src_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("bind failed for UDP socket for 0");
        exit(1);
    }

    if (bind(socks[1].udp_sock, (struct sockaddr *)&socks[1].src_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("bind failed for UDP socket for 1");
        exit(1);
    }

    pthread_mutex_unlock(&lock);
  
    // Start threads
    pthread_t r_thread, s_thread;
    pthread_create(&r_thread, NULL, thread_R, NULL);
    pthread_create(&s_thread, NULL, thread_S, NULL);

    // Start garbage collector
    start_garbage_collector();

    // Wait for threads to complete (this will not happen under normal execution)
    pthread_join(r_thread, NULL);
    pthread_join(s_thread, NULL);


    return 0;
}
