#include "trn_mw_rq.h"
#include "trn_p_rq.h"
#include "macros.h"

/// @brief Calculates CRC64 for each bio sector and writes results to meta->page
/// @details
/// Traverses all bio segments byte-by-byte, accumulating CRC64 (big-endian)
/// for each data sector. Upon completion of each sector, writes
/// the final CRC to the corresponding place in meta->page: the entry of the
/// chunk at part->metadata_offset, and in it the index meta->first_sector.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure for write
/// @param bio  Bio with data for CRC calculation
static void bio_crc_calc(struct trn_mw_rq *meta, struct bio *bio)
{
    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    void *base = kmap_local_page(meta->page);
    struct chunk_metadata *md = base + meta->part->metadata_offset;
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

    kunmap_local(base);
    flush_dcache_page(meta->page);
}

/// @brief Initializes struct trn_mw_rq
/// @details
/// Takes a page for the metadata from the page pool, with its first sector
/// cleared, as only the CRCs are filled in before it goes to disk.
///
/// Sets up part->meta_bio to read the old metadata sector into the second
/// half of the page, to later preserve the CRCs of the neighbouring chunks
/// and of the unmodified sectors. complete_work sets it up again to write
/// updated metadata from the first half of the page. This holds for a write
/// of a whole chunk as well, as its metadata sector is shared.
///
/// Calls bio_crc_calc to calculate new CRCs from data in part->bio.
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

    meta->first_sector = (u8)(align_data_sector(part->bio->bi_iter.bi_sector) - part->index);
    meta->nr_sectors = (u8)bio_sectors(part->bio);
    meta->part = part;
    meta->page = mempool_alloc(dm_ctx->page_pool, GFP_NOIO);
    memzero_page(meta->page, 0, SECTOR_SIZE);
    metadata_bio_init(part, meta->page, SECTOR_SIZE, REQ_OP_READ);

    bio_crc_calc(meta, part->bio);

    DM_DEBUG("meta=%p, first_sector=%u, nr_sectors=%u\n",
             meta,
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
    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    bio_uninit(&meta->part->meta_bio);
    mempool_free(meta->page, meta->part->dm_ctx->page_pool);
}

/// @brief Merges old and new CRCs
/// @details
/// Runs after successful old metadata read via part->meta_bio.
///
/// Copies from the old metadata sector (second half of page) to the new one
/// (first half of page) every CRC but those of the sectors of the current
/// write request: the entries of the neighbouring chunks, and the CRCs of the
/// other sectors of this chunk. CRCs for affected sectors were already
/// calculated in bio_crc_calc during initialization.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure
void update_crc_local(struct trn_mw_rq *meta)
{
    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    __le64 *new_crc = page_address(meta->page);
    __le64 *old_crc = new_crc + SECTOR_SIZE / sizeof(*new_crc);
    unsigned int first = meta->part->metadata_offset / sizeof(*new_crc) + meta->first_sector;

    for (unsigned int i = 0; i < SECTOR_SIZE / sizeof(*new_crc); i++)
    {
        if (i < first || i >= first + meta->nr_sectors)
            new_crc[i] = old_crc[i];
    }
}
