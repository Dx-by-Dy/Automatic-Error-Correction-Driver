#include "trn_mr_rq.h"
#include "trn_p_rq.h"
#include "trn_rq.h"

struct trn_mr_rq *
trn_mr_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx)
{
    int r;

    struct trn_mr_rq *meta;
    meta = kzalloc(sizeof(*meta), GFP_NOIO);
    if (!meta)
    {
        return NULL;
    }

    meta->first_sector = (u8)(align_data_sector(part->bio->bi_iter.bi_sector) - part->index);
    meta->nr_sectors = bio_sectors(part->bio);
    meta->part = part;

    meta->page = alloc_page(GFP_NOIO);
    if (!meta->page)
    {
        kfree(meta);
        return NULL;
    }

    r = metadata_bio_init(&meta->read_bio,
                          meta->page,
                          0,
                          dm_ctx,
                          part,
                          start_metadata_sector(part->bio->bi_iter.bi_sector),
                          (blk_opf_t)REQ_OP_READ);
    if (r)
    {
        pr_info("metadata_bio_init: for read_bio failed\n");
        __free_page(meta->page);
        kfree(meta);
        return NULL;
    }
    meta->read_bio->bi_end_io = trn_p_rq_end_io;

    return meta;
}

void complete_trn_mr_rq(struct trn_mr_rq *meta)
{
    bio_put(meta->read_bio);
    __free_page(meta->page);
    kfree(meta);
}

void trn_mr_rq_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, metadata_work);
    struct trn_rq *req = part->req;
    struct trn_mr_rq *meta = part->meta.read;

    if (atomic_read(&req->failed))
        goto out;

    struct chunk_metadata *md = page_address(meta->page);
    unsigned int sector_idx = meta->first_sector;
    u64 current_crc = 0;
    unsigned int in_sector_pos = 0;

    struct bio_vec bvec;
    struct bvec_iter iter;
    bio_for_each_segment(bvec, part->bio, iter)
    {
        void *addr = kmap_local_page(bvec.bv_page);
        unsigned int bvec_pos = 0;

        while (bvec_pos < bvec.bv_len)
        {
            unsigned int len = min(bvec.bv_len - bvec_pos, SECTOR_SIZE - in_sector_pos);
            current_crc = crc64_be(current_crc, addr + bvec.bv_offset + bvec_pos, len);

            bvec_pos += len;
            in_sector_pos += len;

            if (in_sector_pos == SECTOR_SIZE)
            {
                if (md->crc[sector_idx++] != cpu_to_le64(current_crc))
                {
                    kunmap_local(addr);
                    goto error;
                }
                current_crc = 0;
                in_sector_pos = 0;
            }
        }

        kunmap_local(addr);
    }

    goto out;

error:
    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

    pr_info("CRC check: error!\n");
    pr_info("crc_on_disk[%d] = %llx\n, current_crc = %llx\n", sector_idx - 1, le64_to_cpu(md->crc[sector_idx - 1]), current_crc);

out:
    complete_trn_p_rq(part);
}