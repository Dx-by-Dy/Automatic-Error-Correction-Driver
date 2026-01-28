#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/hdreg.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "ramdisk"
#define RAMDISK_SECTOR_SIZE 512
#define RAMDISK_SIZE (16 * 1024 * 1024) // 16 MB
#define RAMDISK_SECTORS (RAMDISK_SIZE / RAMDISK_SECTOR_SIZE)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("RAM Disk for Linux 6.16");

static int major;
static u8 *ramdisk_data;
static struct gendisk *ramdisk_disk;
static struct request_queue *ramdisk_queue;
static struct blk_mq_tag_set tag_set;

static blk_status_t ramdisk_queue_rq(struct blk_mq_hw_ctx *hctx,
                                     const struct blk_mq_queue_data *bd)
{
    struct request *req = bd->rq;
    blk_status_t status = BLK_STS_OK;
    struct bio_vec bvec;
    struct req_iterator iter;
    sector_t sector = blk_rq_pos(req);
    unsigned long offset = sector * RAMDISK_SECTOR_SIZE;

    blk_mq_start_request(req);

    rq_for_each_segment(bvec, req, iter)
    {
        unsigned int len = bvec.bv_len;
        void *buffer = kmap_local_page(bvec.bv_page) + bvec.bv_offset;

        if (offset + len > RAMDISK_SIZE)
        {
            status = BLK_STS_IOERR;
            kunmap_local(buffer);
            break;
        }

        if (rq_data_dir(req) == WRITE)
            memcpy(ramdisk_data + offset, buffer, len);
        else
            memcpy(buffer, ramdisk_data + offset, len);

        kunmap_local(buffer);
        offset += len;
    }

    blk_mq_end_request(req, status);
    return status;
}

static const struct blk_mq_ops ramdisk_mq_ops = {
    .queue_rq = ramdisk_queue_rq,
};

static int ramdisk_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
    geo->heads = 4;
    geo->sectors = 16;
    geo->cylinders = RAMDISK_SIZE / (geo->heads * geo->sectors * RAMDISK_SECTOR_SIZE);
    geo->start = 0;
    return 0;
}

static const struct block_device_operations ramdisk_fops = {
    .owner = THIS_MODULE,
    .getgeo = ramdisk_getgeo,
};

static int __init ramdisk_init(void)
{
    int ret;
    struct queue_limits lim = {
        .logical_block_size = RAMDISK_SECTOR_SIZE,
    };

    ramdisk_data = vmalloc(RAMDISK_SIZE);
    if (!ramdisk_data)
        return -ENOMEM;

    major = register_blkdev(0, DEVICE_NAME);
    if (major < 0)
    {
        vfree(ramdisk_data);
        return major;
    }

    memset(&tag_set, 0, sizeof(tag_set));
    tag_set.ops = &ramdisk_mq_ops;
    tag_set.nr_hw_queues = 1;
    tag_set.queue_depth = 128;
    tag_set.numa_node = NUMA_NO_NODE;
    tag_set.cmd_size = 0;
    tag_set.flags = 0;

    ret = blk_mq_alloc_tag_set(&tag_set);
    if (ret)
        goto out_unregister;

    ramdisk_disk = blk_alloc_disk(&lim, NUMA_NO_NODE);
    if (!ramdisk_disk)
    {
        ret = -ENOMEM;
        goto out_free_tagset;
    }

    ramdisk_queue = ramdisk_disk->queue;
    ret = blk_mq_init_allocated_queue(&tag_set, ramdisk_queue);
    if (ret)
        goto out_put_disk;

    snprintf(ramdisk_disk->disk_name, DISK_NAME_LEN, DEVICE_NAME);
    ramdisk_disk->fops = &ramdisk_fops;
    set_capacity(ramdisk_disk, RAMDISK_SECTORS);

    ret = device_add_disk(NULL, ramdisk_disk, NULL);
    if (ret)
        goto out_put_disk;

    printk(KERN_INFO "ramdisk: %d MB RAM disk initialized\n",
           RAMDISK_SIZE / 1024 / 1024);
    return 0;

out_put_disk:
    put_disk(ramdisk_disk);
out_free_tagset:
    blk_mq_free_tag_set(&tag_set);
out_unregister:
    unregister_blkdev(major, DEVICE_NAME);
    vfree(ramdisk_data);
    return ret;
}

static void __exit ramdisk_exit(void)
{
    del_gendisk(ramdisk_disk);
    put_disk(ramdisk_disk);
    blk_mq_free_tag_set(&tag_set);
    unregister_blkdev(major, DEVICE_NAME);
    vfree(ramdisk_data);
    printk(KERN_INFO "ramdisk: unloaded\n");
}

module_init(ramdisk_init);
module_exit(ramdisk_exit);
