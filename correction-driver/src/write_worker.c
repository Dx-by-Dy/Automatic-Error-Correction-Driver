#include "write_worker.h"
#include <linux/slab.h>

static void write_handler(struct work_struct *work);

struct write_worker *write_worker_init(struct bio *orig_bio, struct mutex *gl_mutex)
{
    struct write_worker *worker = kmalloc(sizeof(struct write_worker), GFP_KERNEL);
    if (!worker)
        return NULL;

    INIT_WORK(&worker->work, write_handler);
    worker->orig_bio = orig_bio;
    worker->gl_mutex = gl_mutex;
    // spin_lock_init(&worker->list_spinlock);
    // INIT_LIST_HEAD(&worker->queue);

    return worker;
}

static void write_handler(struct work_struct *work)
{
    // struct my_device *dev = container_of(work, struct my_device, work);
    struct bio *crc_bio;

    pr_info("Processing device work\n");
}