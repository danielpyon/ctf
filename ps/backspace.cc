#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>

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

    int ret = !strcmp(s_after, t_after);

    free(s_after);
    free(t_after);

    return ret;
}

// todo: use string
bool backspace_optimized(char* s, char* t) {
    int i = strlen(s) - 1;
    int j = strlen(t) - 1;

    while (i >= 0 && j >= 0) {
        //printf("%c %c\n", s[i], t[j]);

        if (s[i] == '#' || t[j] == '#') {
            int count = 0;
            while (s[i] == '#') {
                count++;
                i--;
            }
            i -= count;

            count = 0;
            while (t[j] == '#') {
                count++;
                j--;
            }
            j -= count;
            continue;
        }

        // printf("%c %c\n", s[i], t[j]);

        if (s[i--] != t[j--])
            return false;
    }

    // puts("---");
    // printf("%c %c\n",s[i],s[j]);
    // printf("%d %d\n",i,j);

    if (i == -1 && j == -1)
        return true;
    return false;
}

bool backspace_optimized2(std::string s, std::string t) {
    int i = s.length() - 1;
    int j = t.length() - 1;
    while (i >= 0 || j >= 0) {
        if ((i >= 0 && s[i] == '#') || (j >= 0 && t[j] == '#')) {
            int count = 0;
            while (i >= 0 && s[i] == '#') {
                count++;
                i--;
            }
            i -= count;

            count = 0;
            while (j >= 0 && t[j] == '#') {
                count++;
                j--;
            }
            j -= count;
            continue;
        }
        if (s[i--] != t[j--])
            return false;
    }

    if (i == -1 && j == -1)
        return true;
    return false;
}

int main() {
    // printf("%d\n", backspace_naive("axy##d#bc#", "abc#"));
    printf("%d\n", backspace_optimized2(std::string("axy##d#bc#"), std::string("abc#")));
    printf("%d\n", backspace_optimized2(std::string("ab##"), std::string("c#d#")));
}