#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    //print pid 

    pid_t pid = getpid();
    printf("pid: %d\n", pid);
    ssize_t bytes_written;
    int fd;
    char *buf0 = "GET /index.html HTTP/1.1\r\n";
    char *buf1 = "Host: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n";
    char *buf2 = "<html><body><h1>Hello, World!</h1></body></html>\r\n";
    char *buf_merged = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n<html><body><h1>Hello, World!</h1></body></html>\r\n";

    char *buf_write = "buf from write\n";
    char *buf_writev = "buf from writev\n";
    int iovcnt;
    char buf_for_ebpf[1024];
    struct iovec iov[3];

    iov[0].iov_base = buf_writev;
    iov[0].iov_len = strlen(buf_writev);
    iov[1].iov_base = buf_for_ebpf;
    iov[1].iov_len = 0;
    iov[2].iov_base = NULL;
    iov[2].iov_len = 0;

    iovcnt = 2;

    while(1){
        sleep(1);
        fd = open("output.txt", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (fd == -1) {
            perror("open");
            return 1;
        }

        printf("writev\n");
        bytes_written = writev(fd, iov, iovcnt);
        if (bytes_written == -1) {
            perror("writev");
            return 1;
        }

        printf("write\n");
        bytes_written = write(fd, buf_write, strlen(buf_write));
        if(bytes_written == -1) {
            perror("write");
            return 1;
        }

        close(fd);
    }

    return 0;
}
