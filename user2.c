#include "ksocket.h"
#include <stdio.h>

int main() {
    // Create KTP socket
    int sock = k_socket(AF_INET, SOCK_KTP, 0);
    if (sock < 0) {
        printf("Failed to create socket\n");
        return 1;
    }

    // Bind socket
    if (k_bind(sock, "127.0.0.1", 8001, "127.0.0.1", 8000) < 0) {
        printf("Failed to bind socket\n");
        return 1;
    }

    // Open file to write received data
    FILE* fp = fopen("received_file.txt", "wb");
    if (!fp) {
        printf("Failed to create output file\n");
        return 1;
    }

    // Receive data
    char buffer[MSG_SIZE];
    int bytes_received;
    
    while (1) {
        bytes_received = k_recvfrom(sock, buffer, MSG_SIZE);
        
        if (bytes_received == 0)
        {
            break;
        }

        if (bytes_received < 0) continue;
        fwrite(buffer, 1, bytes_received, fp);
    }

    fclose(fp);
    k_close(sock);
    return 0;
}
