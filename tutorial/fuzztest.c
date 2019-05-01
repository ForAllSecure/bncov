#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char buf[100] = {0};

    if (argc != 2) {
        printf("USAGE: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        return 2;
    }
    
    if (fgets(buf, sizeof(buf), fp) == NULL) {
        return 3;
    }

    for(char* p = buf; *p != 0; p++) {
        if (p[0] == 'F')
        if (p[1] == 'u')
        if (p[2] == 'z')
        if (p[3] == 'z')
        if (p[4] == 'T')
        if (p[5] == 'e')
        if (p[6] == 's')
        if (p[7] == 't') {
            printf("Aborting\n");
            abort();
        }
    }

    fclose(fp);

    return 0;
}
