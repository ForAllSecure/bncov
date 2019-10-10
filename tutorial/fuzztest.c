#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void fuzz_test(char *buf, int len) {

    char* stop_at = buf + len - 8;

    for(char* p = buf; p < stop_at; p++) {
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
}

int main(int argc, char **argv) {

    char buf[100] = {0};

    if (argc != 2) {
        printf("USAGE: %s <input_file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], 0);
    if (fd == -1) {
      printf("USAGE: %s INPUT_FILE\n", argv[0]);
      return -1;
    }

    ssize_t bytes_read = read(fd, buf, sizeof(buf)-1);
    close(fd);

    if (bytes_read >= 0) {
      fuzz_test(buf, strlen(buf));
    }

    return 0;
}
