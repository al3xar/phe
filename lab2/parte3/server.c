#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>

void vulnerable(int client_sock) {
    char buffer[128];
    read(client_sock, buffer, 512);  // Desbordamiento
}

int main() {
    int sockfd, newsockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(9999);
    puts("==== Echo Server in port 9999 ====");

    bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    listen(sockfd, 5);

    while (1) {
        clilen = sizeof(cli_addr);
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (fork() == 0) {
            // Proceso hijo
            close(sockfd);
            vulnerable(newsockfd);
            write(newsockfd, "Send data: ", 11);
            write(newsockfd, "Done\n", 5);
            puts("Connection closed.");
            close(newsockfd);
            exit(0);
        } else {
            // Proceso padre
            close(newsockfd);
            wait(NULL); // Espera al hijo
        }
    }

    return 0;
}