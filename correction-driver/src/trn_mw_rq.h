#ifndef TRN_MW_RQ_H
#define TRN_MW_RQ_H

#include <linux/types.h>
#include <linux/crc64.h>
#include <linux/bio.h>

#include "alignment.h"
#include "bio_helper.h"

struct trn_p_rq;
struct trn_rq;
struct dm_context;

/// @brief Representation of one chunk's metadata stored on disk
/// @details
/// Located in the metadata sector immediately after DATA_SIZE_SECTORS
/// data sectors of the chunk. Contains CRC64 for each data sector,
/// computed in order of increasing sector index.
struct chunk_metadata
{
    /// @brief CRC64 for each data sector of the chunk
    __le64 crc[DATA_SIZE_SECTORS];
};

/// @brief Structure representing chunk metadata transformation on write
/// @details
/// Created during initialization of trn_p_rq for write operations.
///
/// For partial write (chunk_full == false) before writing new
/// metadata, it's necessary to read the old metadata to update CRC only for the
/// needed sectors. For this, the page is divided into two parts:
///   - [0, METADATA_SIZE_SECTORS * SECTOR_SIZE)                                                — new metadata (write_bio)
///   - [METADATA_SIZE_SECTORS * SECTOR_SIZE, 2 * METADATA_SIZE_SECTORS * SECTOR_SIZE)          — old metadata (read_bio)
///
/// For full write (chunk_full == true) read_bio is not created,
/// as all CRCs of the chunk are recalculated and write_bio is sent directly.
struct trn_mw_rq
{
    /// @brief Bio for reading old chunk metadata from disk
    /// @details Exists only when chunk_full == false.
    struct bio *read_bio;

    /// @brief Bio for writing updated chunk metadata to disk
    struct bio *write_bio;

    /// @brief Reference to the parent struct trn_p_rq for chunk transformation
    struct trn_p_rq *part;

    /// @brief Index of the first data sector of the chunk from which trn_p_rq starts.
    /// Used to compute corresponding metadata for the request.
    u8 first_sector;

    /// @brief Number of data sectors in trn_p_rq.
    /// Used to compute corresponding metadata for the request.
    u8 nr_sectors;

    /// @brief Memory page to store chunk metadata
    /// @details When chunk_full == false the page is divided into two parts:
    /// first — new metadata for writing,
    /// second — old metadata read from disk.
    struct page *page;

    /// @brief Flag indicating full chunk write
    /// @details If true — request covers all DATA_SIZE_SECTORS sectors of the chunk,
    /// otherwise — false.
    bool chunk_full;
};

struct trn_mw_rq *
trn_mw_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx);
void complete_trn_mw_rq(struct trn_mw_rq *meta);
void update_crc_local(struct trn_mw_rq *meta);

#endif
