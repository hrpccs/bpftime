#include <stdio.h>
#include <sys/uio.h>
#include <string.h>

typedef long (*syscall_fn_t)(long, long, long, long, long, long, long);

static syscall_fn_t next_sys_call = NULL;

static long hook_function(long a1, long a2, long a3,
			  long a4, long a5, long a6,
			  long a7)
{
	printf("output from hook_function: syscall number %ld\n", a1);
	if(a1 == 1){
		printf("output from hook_function: syscall number %ld\n", a1);

		char* buf = "writev from intercept write\n";
		    int iovcnt;
    char buf_for_ebpf[1024];
    struct iovec iov[3];

	int fd = a2;

    iov[0].iov_base = buf;
    iov[0].iov_len = strlen(buf);
    iov[1].iov_base = buf_for_ebpf;
    iov[1].iov_len = 0;
    iov[2].iov_base = NULL;
    iov[2].iov_len = 0;

    iovcnt = 2;

	return writev(fd, iov, iovcnt);
	}
	return next_sys_call(a1, a2, a3, a4, a5, a6, a7);
}

int __hook_init(long placeholder __attribute__((unused)),
		void *sys_call_hook_ptr)
{
	printf("output from __hook_init: we can do some init work here\n");

	next_sys_call = *((syscall_fn_t *) sys_call_hook_ptr);
	*((syscall_fn_t *) sys_call_hook_ptr) = hook_function;

	return 0;
}
