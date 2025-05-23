#include <stdio.h>
#include <stdint.h>

static inline uintptr_t stack_cookie(void) {
  uintptr_t v;
  __asm__("mov %%gs :0x14,%0" : "=r"(v));
  return v;
}

int main(void) {
  printf("%#lx\n", (unsigned long) stack_cookie());
  return 0;
}
