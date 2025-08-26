# Assignment12

below is a complete, working example that implements a Linux kernel char device /dev/vicharak providing a dynamic circular queue controlled through IOCTLs. It supports:

SET_SIZE_OF_QUEUE — set queue size (bytes)

PUSH_DATA — push arbitrary bytes from userspace into the queue

POP_DATA — pop bytes from the queue into a userspace buffer (blocking if queue empty)

Blocking behavior: POP_DATA will block until there is at least some data to read. PUSH_DATA will block if there is no free space (so producers and consumers can synchronize).

I give:

Kernel module (vicharak.c) + Makefile.

Three userspace apps: configurator.c, filler.c, reader.c.

Build/installation and run instructions.

Note: The example device name is /dev/vicharak (matching your sample). If you want a different device name, change DEV_NAME in the kernel file and in user programs.

Notes about the kernel code

The struct user_data used in IOCTLs contains int length; char *data; — this matches the userspace struct. The kernel copies that struct from userland, then copies the actual data using copy_from_user/copy_to_user.

The queue is created by SET_SIZE_OF_QUEUE and freed/recreated if called again.

POP_DATA blocks when queue empty (via wait_event_interruptible(queue->read_wait, queue->used > 0)). PUSH_DATA waits for space (so the producer will block if the queue is full). Both wakes / wait queues used to synchronize.

Proper locking with mutex and wait_queue_head_t is used.

Device created is /dev/vicharak by device_create.

Build / install / run instructions

Build kernel module:

make


Insert module (requires root):

sudo insmod vicharak.ko


Check device:

The module creates device /dev/vicharak automatically via device_create. Confirm:

ls -l /dev/vicharak


If device doesn't exist (rare), create it manually using mknod with the correct major/minor (see dmesg or cat /proc/devices), but the module uses device_create which should have created it.

Compile userspace helpers:

gcc -o configurator configurator.c
gcc -o filler filler.c
gcc -o reader reader.c


Initialize queue size:

sudo ./configurator


In one terminal run the reader (this will block if there is no data):

sudo ./reader


In another terminal run the filler:

sudo ./filler


The reader will unblock and print the data pushed.

Remove module when done:

sudo rmmod vicharak
make clean

5) Behavior notes & gotchas

The code implements blocking both for POP_DATA (when empty) and PUSH_DATA (when full). If you prefer PUSH_DATA to return immediately with -ENOSPC instead of blocking, let me know and I can provide that variation.

POP_DATA expects the userspace caller to pass a struct user_data with length set to maximum bytes they want and data pointing to allocated buffer. On return the kernel updates length with actual bytes popped.

IOCTL numbers must match between kernel and userspace; the code uses _IOW / _IOR macros consistent with your examples.

This is example code intended for learning and testing. On production or more robust driver designs you'd want additional input validation and edge-case handling (timeouts, partial-copy semantics, async notification/poll support, etc.).

Always test with care (kernel modules can crash the system if bugs present). Use a VM if you can.
