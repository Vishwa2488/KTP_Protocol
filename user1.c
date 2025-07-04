#include "ksocket.h"
#include <stdio.h>
#include <string.h>
#define BUFFER_SIZE 1000

int main() {
    // Create KTP socket
    int sock = k_socket(AF_INET, SOCK_KTP, 0);
    if (sock < 0) {
        printf("Failed to create socket\n");
        return 1;
    }

    // Bind socket
    if (k_bind(sock, "127.0.0.1", 8000, "127.0.0.1", 8001) < 0) {
        printf("Failed to bind socket\n");
        return 1;
    }

    // Open file to send
    FILE* fp = fopen("testfile.txt", "rb");
    if (!fp) {
        printf("Failed to open file\n");
        return 1;
    }

    // Send file in chunks
    char buffer[MSG_SIZE];
    int bytes_read;
   
    while ((bytes_read = fread(buffer, 1, MSG_SIZE, fp)) > 0) {
        if (k_sendto(sock, buffer, bytes_read) < 0) {
            printf("Failed to send data\n");
            break;
        }
    }

    buffer[0] = '\0';
    if (k_sendto(sock, buffer, 0) < 0)
    {
        printf("Ending failed\n");
    }

    printf("Receiver stopped\n");

    fclose(fp);
    k_close(sock);
    return 0;
}
