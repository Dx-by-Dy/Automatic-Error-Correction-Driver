#include "bio_helper.h"
#include "correction-driver.h"

/// @brief Функция вывода структуры bio
/// @param bio Структура bio
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

int metadata_bio_init(struct bio **bio,
                      struct page *page,
                      unsigned int offset,
                      struct dm_context *dm_ctx,
                      void *private_data,
                      sector_t sector,
                      blk_opf_t opf)
{
    *bio = bio_alloc_bioset(dm_ctx->dev->bdev, 1, opf, GFP_NOIO, dm_ctx->transform_bs);
    if (!(*bio))
        return -ENOMEM;

    (*bio)->bi_iter.bi_sector = sector;
    (*bio)->bi_private = private_data;

    if (bio_add_page(*bio, page, SECTOR_SIZE, offset) != SECTOR_SIZE)
    {
        bio_put(*bio);
        *bio = NULL;
        return -ENOMEM;
    }

    return 0;
}
