#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char* make_string(char* s) {
    char* ret = (char*)malloc(strlen(s) + 1);
    if (ret == NULL)
        return NULL;
    strcpy(ret, s);
    return ret;
}

int my_strlen(char* s) {
    char* t = s;
    while ((*(t++)));
    return t - s;
}

void my_strcpy(char* dst, char* src) {
    int len = my_strlen(src);
    // check if src and dst overlap; if so, copy from the end
    if (dst > src && dst <= src + len) {
        // special case
        src += len;
        dst += len;
        while ((*(dst--) = *(src--)));
        return;
    }

    // normal case
    while ((*(dst++) = *(src++)));
}

void my_strncpy(char* dst, char* src, size_t n) {
    char* start = src;
    while ((*(dst++) = *(src++)) && src - start < n);
}

int my_strcmp(char* s, char* t) {
    return 0;
}

int main() {
    char* a = make_string("cat");
    char* b = make_string("hello");

    my_strcpy(b + 2, b);
    printf("%s\n", b);

    char* c = make_string("doggo");
    my_strncpy(a, c, 4);
    printf("%s\n", a);

    free(a);
    free(b);
    free(c);
}