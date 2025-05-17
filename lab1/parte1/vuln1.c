#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef DNI
  #Error de compilacion, define el DNI
#endif

#define BUFSIZE (64 + (DNI % 23))

void vulnerable() {
  char buffer[BUFSIZE];
  printf("Introduce datos: ");
  gets(buffer);
  printf("Has introducido: %s\n", buffer);
}

int main() {
  vulnerable();
  printf("Exploit failed\n");
  return 0;
}
