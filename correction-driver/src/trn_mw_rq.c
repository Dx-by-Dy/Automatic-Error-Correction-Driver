#include "trn_mw_rq.h"
#include "trn_p_rq.h"
#include "macros.h"

/// @brief Calculates CRC64 for each bio sector and writes results to meta->page
/// @details
/// Traverses all bio segments byte-by-byte, accumulating CRC64 (big-endian)
/// for each data sector. Upon completion of each sector, writes
/// the final CRC to the corresponding place in meta->page, determined
/// by the index meta->first_sector.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure for write
/// @param bio  Bio with data for CRC calculation
static void bio_crc_calc(struct trn_mw_rq *meta, struct bio *bio)
{
    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    struct chunk_metadata *md = kmap_local_page(meta->page);
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
                DM_DEBUG("sector=%llu (+%u on chunk), computed_crc=%llu\n",
                         (unsigned long long)(meta->part->index + sector_idx),
                         sector_idx,
                         current_crc);

                md->crc[sector_idx++] = cpu_to_le64(current_crc);
                current_crc = 0;
                in_sector_pos = 0;
            }
        }

        kunmap_local(addr);
    }

    kunmap_local((void *)md);
    flush_dcache_page(meta->page);
}

/// @brief Initializes struct trn_mw_rq
/// @details
/// Takes a page for the metadata from the page pool, with its first sector
/// cleared, as only the CRCs are filled in before it goes to disk.
///
/// For partial write (chunk_full == false) sets up part->meta_bio to read
/// old metadata into the second half of the page, to later
/// preserve CRC for unmodified sectors. complete_work sets it up again to write
/// updated metadata from the first half of the page.
///
/// For full write (chunk_full == true) the old metadata is not read —
/// part->meta_bio is set up to write all recalculated CRCs at once.
///
/// In both cases, calls bio_crc_calc to calculate new CRCs
/// from data in part->bio.
///
/// Expected execution context - process, may sleep: waits for a page
/// from the pool if memory is short, and never fails.
/// @param meta   Structure to initialize, inside part
/// @param part   Parent struct trn_p_rq
/// @param dm_ctx Driver context
void trn_mw_rq_init(struct trn_mw_rq *meta,
                    struct trn_p_rq *part,
                    struct dm_context *dm_ctx)
{
    DM_DEBUG("part=%p\n", part);

    meta->chunk_full = (bio_sectors(part->bio) == DATA_SIZE_SECTORS);
    meta->first_sector = (u8)(align_data_sector(part->bio->bi_iter.bi_sector) - part->index);
    meta->nr_sectors = (u8)bio_sectors(part->bio);
    meta->part = part;
    meta->page = mempool_alloc(dm_ctx->page_pool, GFP_NOIO);
    memzero_page(meta->page, 0, METADATA_SIZE_SECTORS * SECTOR_SIZE);

    if (meta->chunk_full)
        metadata_bio_init(part, meta->page, 0, REQ_OP_WRITE);
    else
        metadata_bio_init(part, meta->page, METADATA_SIZE_SECTORS * SECTOR_SIZE, REQ_OP_READ);

    bio_crc_calc(meta, part->bio);

    DM_DEBUG("meta=%p, chunk_full=%d, first_sector=%u, nr_sectors=%u\n",
             meta,
             meta->chunk_full,
             meta->first_sector,
             meta->nr_sectors);
    DM_DEBUG_BIO(&part->meta_bio);
}

/// @brief Frees all resources of struct trn_mw_rq
/// @details
/// Releases the metadata bio and returns the page to the pool.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure
void complete_trn_mw_rq(struct trn_mw_rq *meta)
{
    DM_DEBUG("meta=%p chunk_full=%d first_sector=%u nr_sectors=%u\n",
             meta, meta->chunk_full,
             meta->first_sector, meta->nr_sectors);

    bio_uninit(&meta->part->meta_bio);
    mempool_free(meta->page, meta->part->dm_ctx->page_pool);
}

/// @brief Merges old and new CRCs
/// @details
/// Runs after successful old metadata read via part->meta_bio.
///
/// Copies CRCs for sectors unaffected by the current write request
/// from old metadata (second half of page) to new
/// (first half of page). CRCs for affected sectors were already
/// calculated in bio_crc_calc during initialization.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure
void update_crc_local(struct trn_mw_rq *meta)
{
    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    struct chunk_metadata *new_md = page_address(meta->page);
    struct chunk_metadata *old_md = (struct chunk_metadata *)(page_address(meta->page) + METADATA_SIZE_SECTORS * SECTOR_SIZE);

    for (int i = 0; i < DATA_SIZE_SECTORS; i++)
    {
        if (i < meta->first_sector || i >= meta->first_sector + meta->nr_sectors)
            new_md->crc[i] = old_md->crc[i];
    }
}
