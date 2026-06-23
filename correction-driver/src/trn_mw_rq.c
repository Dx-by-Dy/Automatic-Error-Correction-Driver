#include "trn_mw_rq.h"
#include "trn_p_rq.h"
#include "trn_rq.h"
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
/// Allocates memory for trn_mw_rq, a page for metadata, and necessary bios.
///
/// For partial write (chunk_full == false) creates read_bio to read
/// old metadata into the second half of the page, to later
/// preserve CRC for unmodified sectors. Then creates write_bio to write
/// updated metadata from the first half of the page.
///
/// For full write (chunk_full == true) read_bio is not created —
/// all sector CRCs are recalculated and immediately written.
///
/// In both cases, calls bio_crc_calc to calculate new CRCs
/// from data in part->bio.
///
/// Expected execution context - process.
///
/// On error at any stage, frees all previously allocated resources.
/// @param part   Parent struct trn_p_rq
/// @param dm_ctx Driver context
/// @return Pointer to trn_mw_rq on success, NULL on error
struct trn_mw_rq *
trn_mw_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx)
{
    DM_DEBUG("part=%p\n", part);

    int r;
    struct trn_mw_rq *meta;

    meta = kzalloc(sizeof(*meta), GFP_NOIO);
    if (!meta)
    {
        DM_ERR("kzalloc failed\n");
        return NULL;
    }

    meta->chunk_full = (bio_sectors(part->bio) == DATA_SIZE_SECTORS);
    meta->first_sector = (u8)(align_data_sector(part->bio->bi_iter.bi_sector) - part->index);
    meta->nr_sectors = (u8)bio_sectors(part->bio);
    meta->part = part;

    meta->page = alloc_page(GFP_NOIO);
    if (!meta->page)
    {
        DM_ERR("alloc_page failed\n");
        kfree(meta);
        return NULL;
    }

    if (!meta->chunk_full)
    {
        r = metadata_bio_init(&meta->read_bio,
                              meta->page,
                              METADATA_SIZE_SECTORS * SECTOR_SIZE,
                              dm_ctx,
                              part,
                              start_metadata_sector(part->bio->bi_iter.bi_sector),
                              (blk_opf_t)REQ_OP_READ);
        if (r)
        {
            DM_ERR("metadata_bio_init for read_bio failed, err=%d\n", r);
            __free_page(meta->page);
            kfree(meta);
            return NULL;
        }
        meta->read_bio->bi_end_io = trn_p_rq_end_io;

        DM_DEBUG("meta=%p read_bio=%p\n", meta, meta->read_bio);
        DM_DEBUG_BIO(meta->read_bio);
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
        DM_ERR("metadata_bio_init for write_bio failed, err=%d\n", r);
        if (!meta->chunk_full)
            bio_put(meta->read_bio);
        __free_page(meta->page);
        kfree(meta);
        return NULL;
    }

    meta->write_bio->bi_end_io = trn_p_rq_end_io;
    bio_crc_calc(meta, part->bio);

    DM_DEBUG("meta=%p, write_bio=%p, chunk_full=%d, first_sector=%u, nr_sectors=%u\n",
             meta,
             meta->write_bio,
             meta->chunk_full,
             meta->first_sector,
             meta->nr_sectors);
    DM_DEBUG_BIO(meta->write_bio);

    return meta;
}

/// @brief Frees all resources of struct trn_mw_rq
/// @details
/// Frees read_bio (only when chunk_full == false), write_bio,
/// memory page, and the structure itself.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure
void complete_trn_mw_rq(struct trn_mw_rq *meta)
{
    DM_DEBUG("meta=%p write_bio=%p chunk_full=%d "
             "first_sector=%u nr_sectors=%u\n",
             meta, meta->write_bio, meta->chunk_full,
             meta->first_sector, meta->nr_sectors);

    if (!meta->chunk_full)
        bio_put(meta->read_bio);
    bio_put(meta->write_bio);
    __free_page(meta->page);
    kfree(meta);
}

/// @brief Merges old and new CRCs
/// @details
/// Runs after successful old metadata read via read_bio.
///
/// Copies CRCs for sectors unaffected by the current write request
/// from old metadata (second half of page) to new
/// (first half of page). CRCs for affected sectors were already
/// calculated in bio_crc_calc during initialization.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structureых
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