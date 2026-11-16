#include "trn_mr_rq.h"
#include "trn_p_rq.h"
#include "macros.h"
#include "data_crc.h"

/// @brief Initializes struct trn_mr_rq
/// @details
/// Copies both entries of the chunk from the metadata cache, which reads the
/// metadata area of the region first if it is not in RAM.
///
/// Expected execution context - dm_map, may sleep: waits for the metadata
/// area of the region, see metadata_get, and never fails to allocate.
/// @param meta   Structure to initialize, inside part
/// @param part   Parent struct trn_p_rq for chunk transformation
/// @param dm_ctx Driver context
/// @return BLK_STS_OK, or BLK_STS_IOERR if the metadata sector of the chunk does not read in either copy
blk_status_t trn_mr_rq_init(struct trn_mr_rq *meta,
                            struct trn_p_rq *part,
                            struct dm_context *dm_ctx)
{
    DM_DEBUG("part=%p bio_sector=%llu\n", part, (unsigned long long)part->bio->bi_iter.bi_sector);

    meta->first_sector = (u8)(part->sector % DATA_SIZE_SECTORS);
    meta->nr_sectors = bio_sectors(part->bio);
    meta->part = part;

    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    return metadata_copy_entries(dm_ctx->metadata, part->sector, meta->md);
}

/// @brief Verifies CRC of read data against chunk metadata
/// @details
/// Runs as work in the transform_wq after successful completion
/// of the bio reading the data, completed via trn_p_rq_end_io.
///
/// Computes CRC64 for each data sector of bio, from the seed of its logical
/// sector, see data_crc.h, comparing the result with both copies of the entry of the chunk: a sector
/// passes if it matches either. On CRC mismatch, sets the status of the part
/// and outputs error to the log.
///
/// Expected execution context - process.
/// @param meta Metadata transformation structure
void check_crc(struct trn_mr_rq *meta)
{
    struct trn_p_rq *part = meta->part;

    DM_DEBUG("part=%p first_sector=%u nr_sectors=%u\n",
             part, meta->first_sector, meta->nr_sectors);

    const struct chunk_metadata *lead = &meta->md[METADATA_LEAD];
    const struct chunk_metadata *trail = &meta->md[METADATA_TRAIL];
    u64 salt_crc = part->dm_ctx->sb.salt_crc;
    sector_t sector = part->sector;
    unsigned int sector_idx = meta->first_sector;
    u64 current_crc = data_crc_seed(salt_crc, sector);
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
                DM_DEBUG("sector=%llu, sector_idx=%u, lead_crc=%llu, trail_crc=%llu, computed_crc=%llu\n",
                         (unsigned long long)(meta->part->index + sector_idx),
                         sector_idx,
                         (unsigned long long)le64_to_cpu(lead->crc[sector_idx]),
                         (unsigned long long)le64_to_cpu(trail->crc[sector_idx]),
                         (unsigned long long)current_crc);

                if (lead->crc[sector_idx] != cpu_to_le64(current_crc) &&
                    trail->crc[sector_idx] != cpu_to_le64(current_crc))
                {
                    crc_error = true;
                    sector_idx++;
                    kunmap_local(addr);
                    goto out;
                }
                sector_idx++;
                current_crc = data_crc_seed(salt_crc, ++sector);
                in_sector_pos = 0;
            }
        }

        kunmap_local(addr);
        bio_advance_iter_single(part->bio, &iter, bvec.bv_len);
    }

out:
    if (crc_error)
    {
        DM_ERR("CRC mismatch at sector %llu (+%u on chunk): lead_crc=%llu, trail_crc=%llu, computed_crc=%llu\n",
               (unsigned long long)(meta->part->index + sector_idx - 1),
               sector_idx - 1,
               (unsigned long long)le64_to_cpu(lead->crc[sector_idx - 1]),
               (unsigned long long)le64_to_cpu(trail->crc[sector_idx - 1]),
               (unsigned long long)current_crc);

        part->status = BLK_STS_IOERR;

        // Entry point for recovery after CRC mismatch
    }
}
