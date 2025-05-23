#include <stdio.h>
#include <string.h>

void vuln(void)
{
  char buf[16];
  gets(buf);
  puts("Fin.");
}

int main(void)
{
  vuln();
  return 0;
}