#include "bio_helper.h"
#include "write_worker.h"

void write_orig_bio_part_end_io(struct bio *bio)
{
    struct write_request *req = bio->bi_private;

    if (bio->bi_status)
        req->orig_bio->bi_status = bio->bi_status;

    if (atomic_dec_and_test(&req->pending))
    {
        bio_endio(req->orig_bio);
        bio_put(req->orig_bio);
        kfree(req);
    }

    bio_put(bio);
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
