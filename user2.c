/*
Assignment 3 Submission
Name: S Vishwa Gangadhar
Roll number: 22CS10061
Link of the pcap file: https://drive.google.com/drive/folders/1CTGuxU5v1IEo-f_8MRYhTjFstAqmpNf-?usp=drive_link
*/


#include "ksocket.h"
#include <stdio.h>

int main() {
    // Create a KTP socket.
    // For the receiver, bind to 127.0.0.1:8001 and set the destination to 127.0.0.1:8000.
    int sock = k_socket(AF_INET, SOCK_KTP, 0, "127.0.0.1", 8001, "127.0.0.1", 8000);
    if (sock < 0) {
        printf("Failed to create socket\n");
        return 1;
    }

    // Bind the socket.
    if (k_bind(sock, "127.0.0.1", 8001, "127.0.0.1", 8000) < 0) {
        printf("Failed to bind socket\n");
        return 1;
    }

    // Open a file to write the received data.
    FILE* fp = fopen("received_file.txt", "wb");
    if (!fp) {
        printf("Failed to create output file\n");
        return 1;
    }

    // Receive messages until a termination condition.
    char buffer[MSG_SIZE];
    int bytes_received;
    
    while (1) {
        bytes_received = k_recvfrom(sock, buffer, MSG_SIZE);
        if (bytes_received == -1) {
            // No message available; you may sleep briefly and try again.
            continue;
        }

        if (strlen(buffer) == 0)
        {
            break;
        }

        printf("user2: received message of size %d\n", bytes_received);
        // Here we assume that a zero-length message indicates end-of-transmission.
        if (bytes_received == 0)
            break;
        fwrite(buffer, 1, bytes_received, fp);
    }

    fclose(fp);
    k_close(sock);
    return 0;
}
