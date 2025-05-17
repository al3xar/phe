#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[], char *envp[]) {
    printf("argv[0]: %p\n", argv[0]);
    printf("envp[0]: %p\n", envp[0]);
    printf("getenv(\"SHELL\"): %p\n", getenv("SHELL"));
    return 0;
}
