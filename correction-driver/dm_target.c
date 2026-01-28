#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/bvec.h>

#define DM_MSG_PREFIX "proxy_dm"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("DM target for Linux Kernel 6.16");

struct proxy_c
{
    struct dm_dev *dev;
    sector_t data_start;
    sector_t meta_start;
    sector_t meta_sectors;
};

static void submit_clone_bio(struct proxy_c *pc, struct bio *orig, sector_t sector)
{
    struct bio *clone;
    struct bio_vec bv;
    struct bvec_iter iter;

    pr_warn(DM_MSG_PREFIX ": (orig) %llu, %llu\n", (unsigned long long)orig->bi_vcnt, (unsigned long long)orig->bi_max_vecs);

    clone = bio_alloc(pc->dev->bdev, orig->bi_vcnt, orig->bi_opf, GFP_KERNEL);
    if (!clone)
    {
        pr_warn(DM_MSG_PREFIX ": submit_clone_bio failed (alloc)\n");
        return;
    }

    pr_warn(DM_MSG_PREFIX ": (clone) %u, %u\n", clone->bi_vcnt, clone->bi_max_vecs);

    clone->bi_opf = orig->bi_opf;

    bio_for_each_segment(bv, orig, iter)
    {
        if (bio_add_page(clone, bv.bv_page, bv.bv_len, bv.bv_offset) != bv.bv_len)
        {
            bio_put(clone);
            pr_warn(DM_MSG_PREFIX ": submit_clone_bio failed (add_page)\n");
            return;
        }
        pr_warn(DM_MSG_PREFIX ": one success\n");
    }

    bio_set_dev(clone, pc->dev->bdev);
    clone->bi_iter.bi_sector = sector;
    submit_bio(clone);
}

static int proxy_map(struct dm_target *ti, struct bio *bio)
{
    struct proxy_c *pc = ti->private;
    sector_t user_sector;
    sector_t data_sector;
    sector_t meta_sector;

    if (!pc)
    {
        bio_endio(bio);
        return DM_MAPIO_KILL;
    }

    user_sector = bio->bi_iter.bi_sector;
    data_sector = pc->data_start + user_sector;

    submit_clone_bio(pc, bio, data_sector);
    pr_warn(DM_MSG_PREFIX ": first submit\n");

    if (bio_op(bio) == REQ_OP_WRITE)
    {
        if (pc->meta_sectors != 0)
        {
            meta_sector = pc->meta_start + user_sector;
            if (meta_sector < pc->meta_start + pc->meta_sectors)
            {
                submit_clone_bio(pc, bio, meta_sector);
            }
            else
            {
                pr_warn(DM_MSG_PREFIX ": meta sector out of range\n");
            }
        }
    }

    bio_endio(bio);
    return DM_MAPIO_SUBMITTED;
}

static int proxy_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct proxy_c *pc;
    int r;
    unsigned long long tmp;

    if (argc != 4)
    {
        ti->error = "Usage: <dev> <data_start> <meta_start> <meta_sectors>";
        return -EINVAL;
    }

    pc = kzalloc(sizeof(*pc), GFP_KERNEL);
    if (!pc)
        return -ENOMEM;

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &pc->dev);
    if (r)
    {
        ti->error = "dm_get_device failed";
        kfree(pc);
        return r;
    }

    r = kstrtoull(argv[1], 10, &tmp);
    if (r)
    {
        ti->error = "Invalid data_start";
        dm_put_device(ti, pc->dev);
        kfree(pc);
        return r;
    }
    pc->data_start = (sector_t)tmp;

    r = kstrtoull(argv[2], 10, &tmp);
    if (r)
    {
        ti->error = "Invalid meta_start";
        dm_put_device(ti, pc->dev);
        kfree(pc);
        return r;
    }
    pc->meta_start = (sector_t)tmp;

    r = kstrtoull(argv[3], 10, &tmp);
    if (r)
    {
        ti->error = "Invalid meta_sectors";
        dm_put_device(ti, pc->dev);
        kfree(pc);
        return r;
    }
    pc->meta_sectors = (sector_t)tmp;

    ti->private = pc;

    pr_info(DM_MSG_PREFIX ": loaded dev=%s data_start=%llu meta=%llu+%llu\n",
            argv[0],
            (unsigned long long)pc->data_start,
            (unsigned long long)pc->meta_start,
            (unsigned long long)pc->meta_sectors);

    return 0;
}

static void proxy_dtr(struct dm_target *ti)
{
    struct proxy_c *pc = ti->private;
    if (!pc)
        return;

    dm_put_device(ti, pc->dev);
    kfree(pc);
}

static struct target_type proxy_target = {
    .name = "proxy_dm",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = proxy_ctr,
    .dtr = proxy_dtr,
    .map = proxy_map,
};

static int __init proxy_init(void)
{
    return dm_register_target(&proxy_target);
}

static void __exit proxy_exit(void)
{
    dm_unregister_target(&proxy_target);
}

module_init(proxy_init);
module_exit(proxy_exit);
