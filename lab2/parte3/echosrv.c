#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#define PORT 9999

unsigned char global[1024];

void vulnerable(unsigned char *msg, int len)
{
  char buf[128];
  memcpy(buf, msg, len);
  printf("Recibido %d bytes :", len);
  for (size_t i = 0; i < len; i++)
  {
    printf("%02x", msg[i]);
  }
  printf("\n");
}

void handle(int client)
{
  ssize_t r = read(client, global, sizeof(global));
  vulnerable(global, r);
  write(client, global, r);
  close(client);
  puts("Conexion cerrada.");
}

int main(void)
{
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr = {.sin_family = AF_INET,
                             .sin_port = htons(PORT),
                             .sin_addr.s_addr = INADDR_ANY};
  bind(s, (struct sockaddr *)&addr, sizeof(addr));
  listen(s, 1);

  printf("==== Echo Server in port %d ====\n", PORT);
  while (1)
  {
    int c = accept(s, NULL, NULL);
    pid_t pid = fork();
    if (pid = 0)
    { // proceso hijo
      close(s);
      handle(c);
      _exit(0);
    }
    close(c); // padre
  }
}
