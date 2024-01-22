#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
    for (int i = 0; i < 1024-3; i++) {
        if (dup(0)<0)
            printf("error\n");
    }

    int res = fopen("/tmp/exhaust.c", "r");
    printf("%d\n", res);
    
}

