#include "trn_mr_rq.h"
#include "trn_p_rq.h"
#include "macros.h"

/// @brief Initializes struct trn_mr_rq
/// @details
/// Takes a page for the metadata from the page pool and sets up
/// part->meta_bio to read the chunk metadata sector into it.
///
/// Expected execution context - process, may sleep: waits for a page
/// from the pool if memory is short, and never fails.
/// @param meta   Structure to initialize, inside part
/// @param part   Parent struct trn_p_rq for chunk transformation
/// @param dm_ctx Driver context
void trn_mr_rq_init(struct trn_mr_rq *meta,
                    struct trn_p_rq *part,
                    struct dm_context *dm_ctx)
{
    DM_DEBUG("part=%p bio_sector=%llu\n", part, (unsigned long long)part->bio->bi_iter.bi_sector);

    meta->first_sector = (u8)(align_data_sector(part->bio->bi_iter.bi_sector) - part->index);
    meta->nr_sectors = bio_sectors(part->bio);
    meta->part = part;
    meta->metadata_page = mempool_alloc(dm_ctx->page_pool, GFP_NOIO);

    metadata_bio_init(part, meta->metadata_page, 0, REQ_OP_READ);

    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);
    DM_DEBUG_BIO(&part->meta_bio);
}

/// @brief Frees all resources of struct trn_mr_rq
/// @details
/// Releases the metadata bio and returns the page to the pool.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure
void complete_trn_mr_rq(struct trn_mr_rq *meta)
{
    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    bio_uninit(&meta->part->meta_bio);
    mempool_free(meta->metadata_page, meta->part->dm_ctx->page_pool);
}

/// @brief Verifies CRC of read data against chunk metadata
/// @details
/// Runs as work in the transform_wq after successful completion
/// of bio reading data and chunk metadata (both completed via trn_p_rq_end_io).
///
/// Computes CRC64 for each data sector of bio,
/// comparing the result with the corresponding record on disk.
/// On CRC mismatch, sets the status of the part
/// and outputs error to the log.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure
void check_crc(struct trn_mr_rq *meta)
{
    struct trn_p_rq *part = meta->part;

    DM_DEBUG("part=%p first_sector=%u nr_sectors=%u\n",
             part, meta->first_sector, meta->nr_sectors);

    void *base = kmap_local_page(meta->metadata_page);
    struct chunk_metadata *md = base + part->metadata_offset;
    unsigned int sector_idx = meta->first_sector;
    u64 current_crc = 0;
    u64 expected_crc = 0;
    unsigned int in_sector_pos = 0;
    bool crc_error = false;
    struct bvec_iter iter = meta->saved_iter;

    while (iter.bi_size)
    {
        struct bio_vec bvec = bio_iter_iovec(part->bio, iter);
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
                DM_DEBUG("sector=%llu, sector_idx=%u, expected_crc=%llu, computed_crc=%llu\n",
                         (unsigned long long)(meta->part->index + sector_idx),
                         sector_idx,
                         (unsigned long long)le64_to_cpu(md->crc[sector_idx]),
                         (unsigned long long)current_crc);

                if (md->crc[sector_idx++] != cpu_to_le64(current_crc))
                {
                    crc_error = true;
                    expected_crc = le64_to_cpu(md->crc[sector_idx - 1]);
                    kunmap_local(addr);
                    goto out;
                }
                current_crc = 0;
                in_sector_pos = 0;
            }
        }

        kunmap_local(addr);
        bio_advance_iter_single(part->bio, &iter, bvec.bv_len);
    }

out:
    kunmap_local(base);

    if (crc_error)
    {
        DM_ERR("CRC mismatch at sector %llu (+%u on chunk): expected_crc=%llu, computed_crc=%llu\n",
               (unsigned long long)(meta->part->index + sector_idx - 1),
               sector_idx - 1,
               (unsigned long long)expected_crc,
               (unsigned long long)current_crc);

        part->status = BLK_STS_IOERR;

        // Entry point for recovery after CRC mismatch
    }
}
