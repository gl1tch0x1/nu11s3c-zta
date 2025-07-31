#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "FAIL: Usage: linkat_tmpfile tmpdir [final_location]\n");
        return 1;
    }
    int tmpfile_fd = open(argv[1], O_TMPFILE | O_WRONLY, S_IRUSR | S_IWUSR);
    if (tmpfile_fd == -1) {
        perror("FAIL: could not open tmpfile");
        return 1;
    }
    if (argc == 3) {
        int linkat_result = linkat(tmpfile_fd, "", AT_FDCWD, argv[2], AT_EMPTY_PATH);
        if (linkat_result == -1) {
            perror("FAIL: could not link tmpfile into final location");
            close(tmpfile_fd);
            return 1;
        }
    }
    close(tmpfile_fd);
    fprintf(stderr, "PASS\n");
    return 0;
}
