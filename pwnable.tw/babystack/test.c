#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    char buf[4];
    ssize_t n = read(0, buf, sizeof(buf));

    printf("num read: %d\n", n);

    for (int i = 0; i < 4; i++) {
        printf("0x%x ", buf[i]);
    }
    
    printf("\n");
    
    return 0;
}
