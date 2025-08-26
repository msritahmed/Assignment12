// configurator.c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DRIVER_NAME "/dev/vicharak"
#define SET_SIZE_OF_QUEUE _IOW('a', 'a', int * )

int main(void) {
    int fd = open(DRIVER_NAME, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    int size = 1024; // bytes for queue
    int ret = ioctl(fd, SET_SIZE_OF_QUEUE, &size);
    if (ret < 0) {
        perror("ioctl SET_SIZE_OF_QUEUE");
    } else {
        printf("Queue size set to %d bytes\n", size);
    }
    close(fd);
    return (ret < 0);
}
