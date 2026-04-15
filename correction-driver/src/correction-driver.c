#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/bvec.h>
#include <linux/crc64.h>
#include <linux/workqueue.h>

#include "clone_bio.h"
#include "write_worker.h"

#define DM_MSG_PREFIX "correction_dm"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("DM target for Linux Kernel 6.16");

#define METADATA_SIZE 512
#define CRC_SIZE 8 // CRC64

/*
Контекст всего device mapper
*/
struct dm_context
{
    struct dm_dev *dev;
    struct workqueue_struct *write_wq;
    struct mutex gl_mutex;
};

// static int map_on_write(struct bio *bio, struct dm_context *dm_ctx)
// {
//     struct bio *crc_bio;
//     struct bio_vec bvec;
//     struct bvec_iter iter;

//     u8 metadata_buf[METADATA_SIZE];
//     // size_t crc_bytes = bio_sectors(orig) * CRC_SIZE;
//     size_t metadata_offset = 0;

//     u8 sector_buf[SECTOR_SIZE];
//     size_t sector_buf_offset = 0;

//     bio_for_each_segment(bvec, bio, iter)
//     {
//         void *page = kmap_local_page(bvec.bv_page);
//         u8 *ptr = page + bvec.bv_offset;
//         size_t bvec_pos = 0;

//         while (bvec_pos < bvec.bv_len)
//         {

//             size_t copy = min(min(SECTOR_SIZE - sector_buf_offset, bvec.bv_len - bvec_pos), METADATA_SIZE - metadata_offset);
//             memcpy(sector_buf + sector_buf_offset, ptr + bvec_pos, copy);
//             sector_buf_offset += copy;
//             bvec_pos += copy;

//             if (sector_buf_offset == SECTOR_SIZE)
//             {

//                 u64 crc = crc64_be(0, sector_buf, SECTOR_SIZE);
//                 memcpy(crc_buf + metadata_offset, &crc, CRC_SIZE);
//                 metadata_offset += CRC_SIZE;
//                 sector_buf_offset = 0;
//             }
//         }

//         kunmap_local(page);
//     }

//     crc_bio = bio_alloc(bdev, DIV_ROUND_UP(crc_bytes, PAGE_SIZE), EQ_OP_WRITE, GFP_NOIO);
//     if (!crc_bio)
//     {
//         kfree(crc_buf);
//         return NULL;
//     }

//     bio_set_dev(crc_bio, bdev);
//     crc_bio->bi_iter.bi_sector = 0; // TODO:

//     offset = 0;
//     while (offset < crc_bytes)
//     {
//         struct page *page;
//         size_t copy = min((size_t)PAGE_SIZE, crc_bytes - offset);
//         void *page_addr;

//         page = alloc_page(GFP_NOIO);
//         if (!page)
//             goto err;

//         page_addr = kmap_local_page(page);
//         memcpy(page_addr, crc_buf + offset, copy);
//         kunmap_local(page_addr);

//         if (!bio_add_page(crc_bio, page, copy, 0))
//         {
//             __free_page(page);
//             goto err;
//         }

//         offset += copy;
//     }

//     kfree(crc_buf);
//     return crc_bio;

// err:
//     bio_put(crc_bio);
//     kfree(crc_buf);
//     return NULL;
// }

// static void submit_clone_bio(struct proxy_c *pc, struct bio *orig, sector_t sector)
// {
//     struct bio *clone;
//     struct bio_vec bv;
//     struct bvec_iter iter;

//     pr_warn(DM_MSG_PREFIX ": (orig) %llu, %llu\n", (unsigned long long)orig->bi_vcnt, (unsigned long long)orig->bi_max_vecs);

//     clone = bio_alloc(pc->dev->bdev, orig->bi_vcnt, orig->bi_opf, GFP_KERNEL);
//     if (!clone)
//     {
//         pr_warn(DM_MSG_PREFIX ": submit_clone_bio failed (alloc)\n");
//         return;
//     }

//     pr_warn(DM_MSG_PREFIX ": (clone) %u, %u\n", clone->bi_vcnt, clone->bi_max_vecs);

//     clone->bi_opf = orig->bi_opf;

//     bio_for_each_segment(bv, orig, iter)
//     {
//         if (bio_add_page(clone, bv.bv_page, bv.bv_len, bv.bv_offset) != bv.bv_len)
//         {
//             bio_put(clone);
//             pr_warn(DM_MSG_PREFIX ": submit_clone_bio failed (add_page)\n");
//             return;
//         }
//         pr_warn(DM_MSG_PREFIX ": one success\n");
//     }

//     bio_set_dev(clone, pc->dev->bdev);
//     clone->bi_iter.bi_sector = sector;
//     submit_bio(clone);
// }

static int dm_map(struct dm_target *ti, struct bio *bio)
{

    struct dm_context *dm_ctx = ti->private;

    switch (bio_op(bio))
    {
    case REQ_OP_READ:
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_REMAPPED;

    case REQ_OP_WRITE:
        struct write_worker *worker = write_worker_init(bio, &dm_ctx->gl_mutex);
        queue_work(dm_ctx->write_wq, &worker->work);
        return DM_MAPIO_SUBMITTED;

    default:
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_REMAPPED;
    }

    // struct proxy_c *pc = ti->private;
    // sector_t user_sector;
    // sector_t data_sector;
    // sector_t meta_sector;

    // if (!pc)
    // {
    //     bio_endio(bio);
    //     return DM_MAPIO_KILL;
    // }

    // user_sector = bio->bi_iter.bi_sector;
    // data_sector = pc->data_start + user_sector;

    // submit_clone_bio(pc, bio, data_sector);
    // pr_warn(DM_MSG_PREFIX ": first submit\n");

    // if (bio_op(bio) == REQ_OP_WRITE)
    // {
    //     if (pc->meta_sectors != 0)
    //     {
    //         meta_sector = pc->meta_start + user_sector;
    //         if (meta_sector < pc->meta_start + pc->meta_sectors)
    //         {
    //             submit_clone_bio(pc, bio, meta_sector);
    //         }
    //         else
    //         {
    //             pr_warn(DM_MSG_PREFIX ": meta sector out of range\n");
    //         }
    //     }
    // }
}

static int dm_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct dm_context *dm_ctx;
    int r;
    // unsigned long long tmp;

    // if (argc != 4)
    //{
    //     ti->error = "Usage: <dev> <data_start> <meta_start> <meta_sectors>";
    //     return -EINVAL;
    // }

    // r = kstrtoull(argv[1], 10, &tmp);
    // if (r)
    //{
    //     ti->error = "Invalid data_start";
    //     return r;
    // }

    // r = kstrtoull(argv[2], 10, &tmp);
    // if (r)
    //{
    //     ti->error = "Invalid meta_start";
    //     return r;
    // }

    // r = kstrtoull(argv[3], 10, &tmp);
    // if (r)
    //{
    //     ti->error = "Invalid meta_sectors";
    //     return r;
    // }

    dm_ctx = kzalloc(sizeof(*dm_ctx), GFP_KERNEL);
    if (!dm_ctx)
        return -ENOMEM;

    dm_ctx->write_wq = alloc_workqueue("write_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1024);
    if (!dm_ctx->write_wq)
    {
        kfree(dm_ctx);
        return -ENOMEM;
    }

    mutex_init(&dm_ctx->gl_mutex);

    // dm_ctx->data_start = simple_strtoull(argv[1], NULL, 10);
    // dm_ctx->meta_start = simple_strtoull(argv[2], NULL, 10);
    // dm_ctx->meta_sectors = simple_strtoull(argv[3], NULL, 10);

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &dm_ctx->dev);
    if (r)
    {
        ti->error = "dm_get_device failed";
        kfree(dm_ctx);
        return r;
    }
    ti->private = dm_ctx;

    pr_info(DM_MSG_PREFIX ": loaded dev=%s",
            argv[0]
            //(unsigned long long)dm_ctx->data_start,
            //(unsigned long long)dm_ctx->meta_start,
            //(unsigned long long)dm_ctx->meta_sectors
    );

    return 0;
}

static void dm_dtr(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;
    if (!dm_ctx)
        return;

    dm_put_device(ti, dm_ctx->dev);
    flush_workqueue(dm_ctx->write_wq);
    destroy_workqueue(dm_ctx->write_wq);
    kfree(dm_ctx);
}

static struct target_type target = {
    .name = "correction_dm",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = dm_ctr,
    .dtr = dm_dtr,
    .map = dm_map,
};

static int __init dm_init(void)
{
    return dm_register_target(&target);
}

static void __exit dm_exit(void)
{
    dm_unregister_target(&target);
}

module_init(dm_init);
module_exit(dm_exit);
