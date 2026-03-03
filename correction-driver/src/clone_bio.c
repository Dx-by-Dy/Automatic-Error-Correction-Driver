#include <linux/device-mapper.h>
#include "clone_bio.h"

/*
Функция для высвобождения clone
*/
void clone_end_io(struct bio *clone)
{
    struct bio *orig = clone->bi_private;

    if (clone->bi_status)
        bio_io_error(orig);
    else
        bio_endio(orig);

    bio_put(clone);
}

/*
Функция для высвобождения clone
*/
struct bio *clone_bio(struct bio *orig, struct block_device *bdev)
{
    struct bio *clone;
    struct bio_vec bvec;
    struct bvec_iter iter;

    clone = bio_alloc(bdev, bio_segments(orig), orig->bi_opf, GFP_KERNEL);
    if (!clone)
    {
        pr_err("Error in bio_alloc");
        goto err;
    }

    clone->bi_iter.bi_sector = 0;

    bio_for_each_segment(bvec, orig, iter)
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

    clone->bi_end_io = clone_end_io;
    clone->bi_private = orig;

    bio_copy_data(clone, orig);
    return clone;

err_clone:
    bio_put(clone);
err:
    return NULL;
}

/*
Функция для записи bio в dmesg
*/
void print_bio(struct bio *bio)
{
    pr_info("BIO %p\n", bio);
    pr_info("  bi_opf=0x%x\n", bio->bi_opf);
    pr_info("  bi_sector=%llu\n",
            (unsigned long long)bio->bi_iter.bi_sector);
    pr_info("  bi_size=%u\n", bio->bi_iter.bi_size);
    pr_info("  bi_vcnt=%u\n", bio->bi_vcnt);
    pr_info("  bi_status=%d\n", bio->bi_status);
    pr_info("  bi_max_vecs=%llu\n", (unsigned long long)bio->bi_max_vecs);
    pr_info("  bi_bdev_disk_name=%s\n", bio->bi_bdev->bd_disk->disk_name);

    if (bio_has_data(bio))
    {
        struct bio_vec bvec;
        struct bvec_iter iter;

        bio_for_each_segment(bvec, bio, iter)
        {
            pr_info("    segment: page=%p offset=%u len=%u\n",
                    bvec.bv_page,
                    bvec.bv_offset,
                    bvec.bv_len);
        }
    }
}
