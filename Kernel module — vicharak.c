// vicharak.c
// Build as kernel module. Creates /dev/vicharak
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/ioctl.h>

#define DEVICE_NAME "vicharak"
#define CLASS_NAME "vchar"

// IOCTL definitions (match userspace)
#define SET_SIZE_OF_QUEUE _IOW('a', 'a', int *)
#define PUSH_DATA         _IOW('a', 'b', struct user_data *)
#define POP_DATA          _IOR('a', 'c', struct user_data *)

struct user_data {
    int length;        // number of bytes to push/pop (userspace)
    char *data;        // userspace pointer to buffer (userspace)
};

/* Internal circular buffer structure */
struct circ_queue {
    char *buf;
    size_t size;       // capacity in bytes
    size_t head;       // next read index
    size_t tail;       // next write index
    size_t used;       // number of bytes currently stored
    struct mutex lock;
    wait_queue_head_t read_wait;   // waiters for data (pop)
    wait_queue_head_t write_wait;  // waiters for space (push)
};

static dev_t dev_number;
static struct cdev vchar_cdev;
static struct class *vchar_class;
static struct device *vchar_device;

static struct circ_queue *queue = NULL;

static int vchar_open(struct inode *inode, struct file *file)
{
    // Nothing special per-file
    return 0;
}

static int vchar_release(struct inode *inode, struct file *file)
{
    return 0;
}

/* Helper: allocate a queue with given size (bytes) */
static int allocate_queue(size_t size)
{
    struct circ_queue *q;

    if (size == 0)
        return -EINVAL;

    q = kzalloc(sizeof(*q), GFP_KERNEL);
    if (!q)
        return -ENOMEM;

    q->buf = kmalloc(size, GFP_KERNEL);
    if (!q->buf) {
        kfree(q);
        return -ENOMEM;
    }

    q->size = size;
    q->head = q->tail = 0;
    q->used = 0;
    mutex_init(&q->lock);
    init_waitqueue_head(&q->read_wait);
    init_waitqueue_head(&q->write_wait);

    queue = q;
    return 0;
}

/* Helper: free current queue */
static void free_queue(void)
{
    if (!queue) return;
    kfree(queue->buf);
    kfree(queue);
    queue = NULL;
}

/* Push bytes from kbuf into circular buffer; blocks if necessary until space available */
static ssize_t queue_push(const char *kbuf, size_t len)
{
    size_t first_chunk;
    ssize_t written = 0;

    while (written < (ssize_t)len) {
        ssize_t left;
        wait_event_interruptible(queue->write_wait,
            (mutex_trylock(&queue->lock) == 1) || (signal_pending(current)));
        /* Above trylock pattern: we used trylock to avoid sleeping while holding lock.
           But to keep code simple and safe, we'll instead properly lock: */
        if (signal_pending(current))
            return -EINTR;
        /* Actually acquire lock */
        mutex_lock(&queue->lock);

        left = queue->size - queue->used;
        if (left == 0) {
            /* no space: release lock and wait for space */
            mutex_unlock(&queue->lock);
            if (wait_event_interruptible(queue->write_wait, queue->used < queue->size))
                return -EINTR; // interrupted by signal
            continue;
        }

        /* how many bytes we can write now */
        first_chunk = min((size_t)left, min(len - written, queue->size - queue->tail));
        memcpy(queue->buf + queue->tail, kbuf + written, first_chunk);
        queue->tail = (queue->tail + first_chunk) % queue->size;
        queue->used += first_chunk;
        written += first_chunk;

        mutex_unlock(&queue->lock);

        /* wake up readers */
        wake_up_interruptible(&queue->read_wait);
    }

    return written;
}

/* Pop up to len bytes into kbuf. If queue empty, block until at least 1 byte available. */
static ssize_t queue_pop(char *kbuf, size_t len)
{
    size_t first_chunk;
    ssize_t read = 0;

    /* Wait until there's at least some data */
    if (wait_event_interruptible(queue->read_wait, queue->used > 0))
        return -EINTR;

    while (read < (ssize_t)len) {
        size_t avail;

        mutex_lock(&queue->lock);
        avail = queue->used;
        if (avail == 0) {
            /* nothing more to read */
            mutex_unlock(&queue->lock);
            break;
        }

        first_chunk = min((size_t)avail, min(len - read, queue->size - queue->head));
        memcpy(kbuf + read, queue->buf + queue->head, first_chunk);
        queue->head = (queue->head + first_chunk) % queue->size;
        queue->used -= first_chunk;
        read += first_chunk;
        mutex_unlock(&queue->lock);

        wake_up_interruptible(&queue->write_wait);
    }

    return read;
}

/* ioctl handler */
static long vchar_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret;
    int usersize;
    struct user_data ud;

    switch (cmd) {
    case SET_SIZE_OF_QUEUE:
        if (!arg)
            return -EINVAL;
        if (copy_from_user(&usersize, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        /* reallocate queue if exists */
        if (queue) {
            free_queue();
        }
        ret = allocate_queue((size_t)usersize);
        if (ret)
            return ret;
        return 0;

    case PUSH_DATA:
        if (!queue)
            return -EINVAL;
        if (copy_from_user(&ud, (struct user_data __user *)arg, sizeof(ud)))
            return -EFAULT;
        if (ud.length <= 0 || !ud.data)
            return -EINVAL;

        /* allocate a kernel buffer and copy data from user pointer */
        {
            char *kbuf = kmalloc(ud.length, GFP_KERNEL);
            if (!kbuf)
                return -ENOMEM;
            if (copy_from_user(kbuf, ud.data, ud.length)) {
                kfree(kbuf);
                return -EFAULT;
            }
            /* push into queue (may block until space) */
            ret = queue_push(kbuf, ud.length);
            kfree(kbuf);
            if (ret < 0)
                return ret;
            return 0;
        }

    case POP_DATA:
        if (!queue)
            return -EINVAL;
        if (copy_from_user(&ud, (struct user_data __user *)arg, sizeof(ud)))
            return -EFAULT;
        if (ud.length <= 0 || !ud.data)
            return -EINVAL;

        {
            char *kbuf = kmalloc(ud.length, GFP_KERNEL);
            ssize_t got;
            if (!kbuf)
                return -ENOMEM;

            /* pop (blocks if empty) */
            got = queue_pop(kbuf, ud.length);
            if (got < 0) {
                kfree(kbuf);
                return got;
            }

            /* copy popped data to user's buffer */
            if (copy_to_user(ud.data, kbuf, got)) {
                kfree(kbuf);
                return -EFAULT;
            }

            /* write back actual length popped */
            ud.length = got;
            if (copy_to_user((struct user_data __user *)arg, &ud, sizeof(ud))) {
                kfree(kbuf);
                return -EFAULT;
            }

            kfree(kbuf);
            return got;
        }

    default:
        return -ENOTTY;
    }

    return 0;
}

static const struct file_operations vchar_fops = {
    .owner = THIS_MODULE,
    .open = vchar_open,
    .release = vchar_release,
    .unlocked_ioctl = vchar_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = vchar_ioctl,
#endif
};

static int __init vchar_init(void)
{
    int ret;
    ret = alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("vicharak: failed to alloc chrdev\n");
        return ret;
    }

    cdev_init(&vchar_cdev, &vchar_fops);
    vchar_cdev.owner = THIS_MODULE;
    ret = cdev_add(&vchar_cdev, dev_number, 1);
    if (ret) {
        unregister_chrdev_region(dev_number, 1);
        pr_err("vicharak: cdev_add failed\n");
        return ret;
    }

    vchar_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(vchar_class)) {
        cdev_del(&vchar_cdev);
        unregister_chrdev_region(dev_number, 1);
        pr_err("vicharak: class_create failed\n");
        return PTR_ERR(vchar_class);
    }

    vchar_device = device_create(vchar_class, NULL, dev_number, NULL, DEVICE_NAME);
    if (IS_ERR(vchar_device)) {
        class_destroy(vchar_class);
        cdev_del(&vchar_cdev);
        unregister_chrdev_region(dev_number, 1);
        pr_err("vicharak: device_create failed\n");
        return PTR_ERR(vchar_device);
    }

    pr_info("vicharak: module loaded, device /dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit vchar_exit(void)
{
    free_queue();
    device_destroy(vchar_class, dev_number);
    class_destroy(vchar_class);
    cdev_del(&vchar_cdev);
    unregister_chrdev_region(dev_number, 1);
    pr_info("vicharak: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Char device with dynamic circular queue via IOCTLs");
module_init(vchar_init);
module_exit(vchar_exit);
