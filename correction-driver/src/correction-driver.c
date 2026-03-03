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

static void print_bio(struct bio *bio)
{
    pr_err("BIO %p\n", bio);
    pr_err("  bi_opf=0x%x\n", bio->bi_opf);
    pr_err("  bi_sector=%llu\n",
           (unsigned long long)bio->bi_iter.bi_sector);
    pr_err("  bi_size=%u\n", bio->bi_iter.bi_size);
    pr_err("  bi_vcnt=%u\n", bio->bi_vcnt);
    pr_err("  bi_status=%d\n", bio->bi_status);
    pr_err("  bi_max_vecs=%llu\n", (unsigned long long)bio->bi_max_vecs);

    // if (bio->bi_bdev)
    //     pr_err("  bi_bdev=%s\n",
    //            bio_devname(bio, (char[64]){0}));

    if (bio_has_data(bio))
    {
        struct bio_vec bvec;
        struct bvec_iter iter;

        bio_for_each_segment(bvec, bio, iter)
        {
            pr_err("    segment: page=%p offset=%u len=%u\n",
                   bvec.bv_page,
                   bvec.bv_offset,
                   bvec.bv_len);
        }
    }
}

static void proxy_end_io(struct bio *clone)
{
    struct bio *orig = clone->bi_private;

    if (clone->bi_status)
        bio_io_error(orig);
    else
        bio_endio(orig);

    bio_put(clone);
}

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

static int proxy_map(struct dm_target *ti, struct bio *bio)
{

    struct proxy_c *pc = ti->private;
    struct bio_vec bvec;
    struct bvec_iter iter;
    int r;

    pr_err("Orig");
    print_bio(bio);

    struct bio *clone;

    clone = bio_alloc(pc->dev->bdev, bio_segments(bio), bio->bi_opf, GFP_KERNEL);
    if (!clone)
    {
        pr_err("Error in bio_alloc");
        goto err;
    }

    bio_set_dev(clone, pc->dev->bdev);
    clone->bi_iter.bi_sector = 0;

    bio_for_each_segment(bvec, bio, iter)
    {
        struct page *page;

        page = alloc_page(GFP_NOIO);
        if (!page)
        {
            pr_err("Error in alloc_page");
            goto err_clone;
        }

        if (!bio_add_page(clone, page,
                          bvec.bv_len,
                          bvec.bv_offset))
        {
            pr_err("Error in bio_add_page");
            __free_page(page);
            goto err_clone;
        }
    }

    clone->bi_end_io = proxy_end_io;
    clone->bi_private = bio;

    bio_copy_data(clone, bio);

    pr_err("Clone");
    print_bio(clone);

    submit_bio(clone);

    return DM_MAPIO_SUBMITTED;

err_clone:
    bio_put(clone);
err:
    bio_io_error(bio);
    return DM_MAPIO_KILL;

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

    r = kstrtoull(argv[1], 10, &tmp);
    if (r)
    {
        ti->error = "Invalid data_start";
        return r;
    }

    r = kstrtoull(argv[2], 10, &tmp);
    if (r)
    {
        ti->error = "Invalid meta_start";
        return r;
    }

    r = kstrtoull(argv[3], 10, &tmp);
    if (r)
    {
        ti->error = "Invalid meta_sectors";
        return r;
    }

    pc = kzalloc(sizeof(*pc), GFP_KERNEL);
    if (!pc)
        return -ENOMEM;

    pc->data_start = simple_strtoull(argv[1], NULL, 10);
    pc->meta_start = simple_strtoull(argv[2], NULL, 10);
    pc->meta_sectors = simple_strtoull(argv[3], NULL, 10);

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &pc->dev);
    if (r)
    {
        ti->error = "dm_get_device failed";
        kfree(pc);
        return r;
    }
    ti->private = pc;

    pr_err(DM_MSG_PREFIX ": loaded dev=%s data_start=%llu meta=%llu+%llu\n",
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
