#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void apply_backspace(char* dst, char* src, int len) {
    int idx = 0;
    for (int i = 0; src[i]; i++) {
        if (idx < 0) {
            fprintf(stderr, "too many backspaces\n");
            exit(-1);
        }

        if (src[i] != '#') {
            dst[idx] = src[i];
            idx++;
        } else {
            idx--;
        }
    }
}

int backspace_naive(char* s, char* t) {
    int s_len = strlen(s);
    int t_len = strlen(t);

    char* s_after = (char*)malloc(s_len);
    char* t_after = (char*)malloc(t_len);

    // axy##d#bc#
    apply_backspace(s_after, s, s_len);
    apply_backspace(t_after, t, t_len);

    printf("%s\n", s_after);
    printf("%s\n", t_after);

    int ret = !strcmp(s_after, t_after);

    free(s_after);
    free(t_after);

    return ret;
}

int backspace_optimized(char* s, char* t) {
    return 0;
}

int main() {
    printf("%d\n", backspace_naive("axy##d#bc#", "abc#"));
}