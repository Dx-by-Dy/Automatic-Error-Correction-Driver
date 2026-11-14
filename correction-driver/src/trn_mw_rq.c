#include "trn_mw_rq.h"
#include "trn_p_rq.h"
#include "macros.h"

/// @brief Calculates CRC64 for each bio sector and keeps the results in meta->crc
/// @details
/// Traverses all bio segments byte-by-byte, accumulating CRC64 (big-endian)
/// for each data sector. Upon completion of each sector, keeps the final CRC
/// at the index of the sector in the chunk, starting with meta->first_sector.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure for write
/// @param bio  Bio with data for CRC calculation
static void bio_crc_calc(struct trn_mw_rq *meta, struct bio *bio)
{
    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

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

                meta->crc[sector_idx++] = cpu_to_le64(current_crc);
                current_crc = 0;
                in_sector_pos = 0;
            }
        }

        kunmap_local(addr);
    }
}

/// @brief Initializes struct trn_mw_rq
/// @details
/// Calculates the CRCs of the data in part->bio and sets up part->meta_bio to
/// write the leading metadata sector of the chunk from the area. This holds for
/// a write of a whole chunk as well, as its metadata sector is shared. If the
/// sector failed to read in the leading copy, the area holds it from the
/// trailing one, so the write puts it right.
///
/// Expected execution context - the worker of the cache.
/// @param meta Structure to initialize, inside part
/// @param part Parent struct trn_p_rq
/// @param area The metadata area of the region of the chunk, held by the caller
/// @return BLK_STS_OK, or BLK_STS_IOERR if the metadata sector of the chunk did not read in
///         either copy, so its other entries are not known and it cannot be written
blk_status_t trn_mw_rq_init(struct trn_mw_rq *meta,
                            struct trn_p_rq *part,
                            struct metadata_area *area)
{
    struct page *page;
    unsigned int offset;

    DM_DEBUG("part=%p\n", part);

    meta->first_sector = (u8)(part->sector % DATA_SIZE_SECTORS);
    meta->nr_sectors = (u8)bio_sectors(part->bio);
    meta->part = part;
    meta->area = area;

    page = metadata_sector_page(area, METADATA_LEAD, part->sector, &offset);
    metadata_bio_init(part, page, offset, metadata_write_opf(part->bio));

    bio_crc_calc(meta, part->bio);

    DM_DEBUG("meta=%p, first_sector=%u, nr_sectors=%u\n",
             meta,
             meta->first_sector,
             meta->nr_sectors);
    DM_DEBUG_BIO(&part->meta_bio);

    if (metadata_sector_bad(area, part->sector))
        return BLK_STS_IOERR;

    if (metadata_sector_single(area, part->sector))
        DM_WARN_LIMIT("chunk %llu is written with one copy of its metadata\n",
                      (unsigned long long)(part->sector / DATA_SIZE_SECTORS));

    return BLK_STS_OK;
}

/// @brief Puts the new CRCs into the leading entry of the chunk in the metadata area
/// @details
/// Changes only the CRCs of the sectors of this write; the entries of the
/// neighbouring chunks and the CRCs of the other sectors of this chunk stay as
/// the area holds them, which is what the device below holds. Called just
/// before part->meta_bio is submitted, when no other write of the metadata
/// sector is in flight. No read of the chunk is in flight either, and none
/// starts until the write back ends, so nobody reads the entry meanwhile.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure
void update_crc_local(struct trn_mw_rq *meta)
{
    struct trn_p_rq *part = meta->part;
    struct chunk_metadata *md = metadata_entry(meta->area, METADATA_LEAD, part->sector);
    unsigned int offset;

    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    for (unsigned int i = meta->first_sector; i < meta->first_sector + meta->nr_sectors; i++)
        md->crc[i] = meta->crc[i];

    flush_dcache_page(metadata_sector_page(meta->area, METADATA_LEAD, part->sector, &offset));
}
