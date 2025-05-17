#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9999

// Función vulnerable: copia sin control a un buffer pequeño (buffer overflow)
void vulnerable_function(char *input)
{
  char buffer[128];
  // Sin control de tamaño, un clásico.
  strcpy(buffer, input);
  printf("Recibido: %s\n", buffer);
}

void handle_client(int client_sock)
{
  char recv_buffer[512];
  int n = read(client_sock, recv_buffer, sizeof(recv_buffer) - 1);
  if (n > 0)
  {
    recv_buffer[n] = '\0';
    vulnerable_function(recv_buffer);
  }
  close(client_sock);
}

int main()
{
  int server_fd, client_sock;
  struct sockaddr_in address;
  socklen_t addr_len = sizeof(address);

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1)
  {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
  {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 5) < 0)
  {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  printf("Servidor escuchando en puerto %d...\n", PORT);

  while (1)
  {
    client_sock = accept(server_fd, (struct sockaddr *)&address, &addr_len);
    if (client_sock < 0)
    {
      perror("accept");
      continue;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
      perror("fork");
      close(client_sock);
      continue;
    }

    if (pid == 0)
    {
      // Proceso hijo maneja la conexión
      close(server_fd);
      handle_client(client_sock);
      exit(0);
    }
    else
    {
      // Proceso padre cierra el socket del cliente y sigue esperando
      close(client_sock);
    }
  }

  close(server_fd);
  return 0;
}
