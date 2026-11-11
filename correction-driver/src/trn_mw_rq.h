#ifndef TRN_MW_RQ_H
#define TRN_MW_RQ_H

#include <linux/types.h>
#include <linux/crc64.h>
#include <linux/bio.h>

#include "alignment.h"
#include "bio_helper.h"

struct trn_p_rq;
struct dm_context;

/// @brief Representation of one chunk's metadata stored on disk
/// @details
/// An entry in the metadata sector of the chunk, at metadata_offset, next to
/// the entries of its neighbours. Contains CRC64 for each data sector,
/// computed in order of increasing sector index.
struct chunk_metadata
{
    /// @brief CRC64 for each data sector of the chunk
    __le64 crc[DATA_SIZE_SECTORS];
};

static_assert(sizeof(struct chunk_metadata) == METADATA_ENTRY_SIZE, "the entry of a chunk has a fixed size");

/// @brief Structure representing chunk metadata transformation on write
/// @details
/// Part of trn_p_rq for write operations.
///
/// The metadata sector holds the entries of the neighbouring chunks as well,
/// and a partial write keeps the CRCs of the other sectors of its own chunk,
/// so the old sector is read first and only the CRCs of the written sectors
/// change. For this, the page is divided into two parts:
///   - [0, SECTOR_SIZE)               — new metadata sector (written)
///   - [SECTOR_SIZE, 2 * SECTOR_SIZE) — old metadata sector (read)
///
/// part->meta_bio first reads the old metadata, then is set up again to write
/// the new metadata, so only one metadata bio is in flight at a time. Two
/// writes of the same metadata sector must not be in flight at once, or one
/// would lose the CRCs of the other: the cache sends them one at a time.
struct trn_mw_rq
{
    /// @brief Reference to the parent struct trn_p_rq for chunk transformation
    struct trn_p_rq *part;

    /// @brief Index of the first data sector of the chunk from which trn_p_rq starts.
    /// Used to compute corresponding metadata for the request.
    u8 first_sector;

    /// @brief Number of data sectors in trn_p_rq.
    /// Used to compute corresponding metadata for the request.
    u8 nr_sectors;

    /// @brief Memory page to store the metadata sector, from dm_context->page_pool
    /// @details The page is divided into two parts:
    /// first — new metadata for writing,
    /// second — old metadata read from disk.
    struct page *page;
};

/// @brief Operation and flags of the bio that writes the metadata of a chunk
/// @details
/// A FUA write is durable once it completes, so its metadata has to be FUA as
/// well: the data bio is the upper bio and keeps the flag by itself.
/// @param data The data bio of the part
/// @return REQ_OP_WRITE, with REQ_FUA if the data bio has it
static inline blk_opf_t metadata_write_opf(const struct bio *data)
{
    return REQ_OP_WRITE | (data->bi_opf & REQ_FUA);
}

void trn_mw_rq_init(struct trn_mw_rq *meta,
                    struct trn_p_rq *part,
                    struct dm_context *dm_ctx);
void complete_trn_mw_rq(struct trn_mw_rq *meta);
void update_crc_local(struct trn_mw_rq *meta);

#endif
