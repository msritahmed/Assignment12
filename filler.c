filler.c
// filler.c
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define DRIVER_NAME "/dev/vicharak"
#define PUSH_DATA _IOW('a', 'b', struct data * )

struct data {
    int length;
    char *data;
};

int main(void) {
    int fd = open(DRIVER_NAME, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    const char *msg = "hello-from-filler";
    int len = strlen(msg);

    struct data d;
    d.length = len;
    d.data = malloc(len);
    if (!d.data) {
        perror("malloc");
        close(fd);
        return 1;
    }
    memcpy(d.data, msg, len);

    int ret = ioctl(fd, PUSH_DATA, &d);
    if (ret < 0) {
        perror("ioctl PUSH_DATA");
    } else {
        printf("Pushed %d bytes\n", len);
    }

    free(d.data);
    close(fd);
    return (ret < 0);
}

reader.c
// reader.c
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define DRIVER_NAME "/dev/vicharak"
#define POP_DATA _IOR('a', 'c', struct data * )

struct data {
    int length;
    char *data;
};

int main(void) {
    int fd = open(DRIVER_NAME, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    int want = 32; // request up to 32 bytes
    struct data d;
    d.length = want;
    d.data = malloc(want+1);
    if (!d.data) {
        perror("malloc");
        close(fd);
        return 1;
    }
    memset(d.data, 0, want+1);

    int ret = ioctl(fd, POP_DATA, &d);
    if (ret < 0) {
        perror("ioctl POP_DATA");
    } else {
        // ioctl returns number of bytes popped (or set in d.length)
        int got = d.length;
        d.data[got] = '\0';
        printf("Popped %d bytes: '%s'\n", got, d.data);
    }

    free(d.data);
    close(fd);
    return (ret < 0);
}
