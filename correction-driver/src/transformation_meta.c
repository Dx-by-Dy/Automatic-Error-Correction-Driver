#include "transformation_meta.h"
#include "transformation_part.h"
#include "transformation.h"

static void bio_crc_calc(struct transformation_meta *meta, struct bio *bio)
{
    struct chunk_metadata *md = page_address(meta->page);
    unsigned int sector_idx = meta->first_sector;
    u64 current_crc = 0;
    unsigned int in_sector_pos = 0;

    struct bio_vec bvec;
    struct bvec_iter iter;
    bio_for_each_segment(bvec, bio, iter)
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
                md->crc[sector_idx++] = cpu_to_le64(current_crc);
                current_crc = 0;
                in_sector_pos = 0;
            }
        }

        kunmap_local(addr);
    }
}

struct transformation_meta *
transformation_meta_init(struct transformation_part *part,
                         struct transformation_request *req,
                         struct dm_context *dm_ctx)
{
    switch (part->type)
    {
    case TRANSFORM_READ:
        return NULL;

    case TRANSFORM_WRITE:
        int r;

        struct transformation_meta *meta;
        meta = kzalloc(sizeof(*part->meta), GFP_NOIO);
        if (!meta)
        {
            return NULL;
        }

        meta->chunk_full = (bio_sectors(part->bio) == DATA_SIZE_SECTORS);
        meta->first_sector = (u8)(align_data_sector(part->bio->bi_iter.bi_sector) - part->index);
        meta->nr_sectors = bio_sectors(part->bio);

        meta->page = alloc_page(GFP_NOIO);
        if (!meta->page)
        {
            kfree(meta);
            return NULL;
        }

        if (!meta->chunk_full)
        {
            meta->chunk_full = false;
            r = metadata_bio_init(&meta->read_bio,
                                  meta->page,
                                  SECTOR_SIZE,
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
            meta->read_bio->bi_end_io = transformation_meta_read_end_io;
        }

        r = metadata_bio_init(&meta->write_bio,
                              meta->page,
                              0,
                              dm_ctx,
                              part,
                              start_metadata_sector(part->bio->bi_iter.bi_sector),
                              (blk_opf_t)REQ_OP_WRITE);
        if (r)
        {
            pr_info("metadata_bio_init: for write_bio failed\n");
            if (!meta->chunk_full)
                bio_put(meta->read_bio);
            __free_page(meta->page);
            kfree(meta);
            return NULL;
        }
        meta->write_bio->bi_end_io = transformation_end_io;

        bio_crc_calc(meta, part->bio);

        return meta;
    }

    return NULL;
}

void complete_meta(struct transformation_meta *meta)
{
    if (!meta)
        return;

    if (!meta->chunk_full)
        bio_put(meta->read_bio);
    bio_put(meta->write_bio);
    __free_page(meta->page);
    kfree(meta);
}

void transformation_meta_read_end_io(struct bio *bio)
{
    struct transformation_part *part = bio->bi_private;
    struct transformation_request *req = part->req;
    struct transformation_meta *meta = part->meta;

    if (bio->bi_status != BLK_STS_OK)
    {
        if (!atomic_xchg(&req->failed, 1))
            req->status = bio->bi_status;

        if (atomic_dec_and_test(&part->pending))
            complete_part(part);

        if (atomic_dec_and_test(&req->pending))
            complete_request(req);

        return;
    }

    struct chunk_metadata *new_md = page_address(meta->page);
    struct chunk_metadata *old_md = (struct chunk_metadata *)(page_address(meta->page) + SECTOR_SIZE);

    for (int i = 0; i < DATA_SIZE_SECTORS; i++)
    {
        if (i < meta->first_sector || i >= meta->first_sector + meta->nr_sectors)
            new_md->crc[i] = old_md->crc[i];
    }

    submit_bio(meta->write_bio);
}