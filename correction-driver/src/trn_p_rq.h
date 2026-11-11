#ifndef TRN_P_RQ_H
#define TRN_P_RQ_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>

#include "corrdm.h"
#include "cache.h"
#include "alignment.h"
#include "trn_mw_rq.h"
#include "trn_mr_rq.h"

/// @brief Chunk transformation type
/// @details Defines the direction of the I/O operation:
/// reading data followed by CRC verification, or
/// writing data with metadata updates.
enum trn_p_type
{
    TRANSFORM_READ,
    TRANSFORM_WRITE,
};

/// @brief Lifecycle state of trn_p_rq
enum trn_p_state
{
    /// @brief The data bio and the first metadata bio are about to be submitted or are in flight.
    SUBMITTED,

    /// @brief (TRANSFORM_WRITE only) the old metadata sector has been read;
    /// local CRC is being updated in meta.write.page and on disk via meta_bio.
    CRC_UPDATE,
};

/// @brief Union of read and write metadata structures
/// @details The active field type is determined by the type field in trn_p_rq.
union trn_m_rq
{
    struct trn_mw_rq write;
    struct trn_mr_rq read;
};

/// @brief Structure for single chunk transformation
/// @details
/// Represents a processing unit for a single chunk. Device mapper splits
/// requests at chunk boundaries (ti->max_io_len), so each bio passed to dm_map
/// stays within one data chunk.
///
/// Lives in the per-bio data of that bio (ti->per_io_data_size), so it cannot
/// fail to allocate, and it is freed along with the bio: nothing may touch it
/// after bio_endio at the end of complete_work. Its metadata structure and
/// metadata bio are embedded in it, and the metadata page comes from a mempool,
/// so nothing on the I/O path can fail to allocate.
///
/// A part does not keep other parts of its chunk away by itself: the cache does.
/// A read is in the tree of reads of the cache while in flight, a write back of
/// the chunk waits for it, and the write back jobs of one chunk go one at a time.
///
/// Lifecycle:
///   1. trn_p_rq_init         — bio and metadata initialization
///   2. submit_work           — submitting bios to the underlying device
///   3. complete_work         — see details of the complete_work field
///
/// The pending counter tracks the number of outstanding bios:
/// initialized to 2 during initialization (data bio + metadata bio).
/// When both complete via trn_p_rq_end_io, complete_work is invoked.
struct trn_p_rq
{
    /// @brief Work item for submitting bios to the underlying device
    struct work_struct submit_work;

    /// @brief Work item for advancing the state machine and eventually finalizing the structure lifecycle
    /// @details For TRANSFORM_READ: leaves the tree of reads of the cache and triggers CRC verification
    ///          (check_crc), followed by resource cleanup.
    ///          For TRANSFORM_WRITE (old metadata sector read): triggers local CRC update (update_crc_local)
    ///          and submits meta_bio again to write the metadata.
    ///          For TRANSFORM_WRITE (metadata written): triggers resource cleanup.
    struct work_struct complete_work;

    /// @brief Driver context
    struct dm_context *dm_ctx;

    /// @brief bio containing chunk data (excluding metadata), the one passed to dm_map
    struct bio *bio;

    /// @brief bi_end_io of bio set by device mapper, restored to complete it
    bio_end_io_t *orig_end_io;

    /// @brief Status of the part, given to bio on completion
    /// @details Any error of the data or metadata bios, or a CRC mismatch.
    blk_status_t status;

    /// @brief Chunk index (physical sector of the start of the chunk data area)
    unsigned long index;

    /// @brief Physical sector that holds the metadata of the chunk, shared with its neighbours
    sector_t metadata_sector;

    /// @brief Offset in bytes of the entry of the chunk in its metadata sector
    unsigned int metadata_offset;

    /// @brief (TRANSFORM_READ only) the read in the tree of reads of the cache, see cache_read
    struct cache_range range;

    /// @brief Counter of outstanding bios: data bio + metadata bio
    /// @details Initialized to 2. When it reaches 0, complete_work is invoked.
    /// Can be incremented from 0 to 1 after a successful read of the old metadata during
    /// TRANSFORM_WRITE to re-invoke complete_work after the metadata is written.
    atomic_t pending;

    /// @brief Current lifecycle state
    enum trn_p_state state;

    /// @brief Transformation type: read or write
    enum trn_p_type type;

    /// @brief Chunk metadata structure (read or write depending on type)
    union trn_m_rq meta;

    /// @brief Bio for the metadata sector of the chunk
    /// @details Set up by metadata_bio_init. A write reads the old metadata sector
    /// with it, then sets it up again to write the new one.
    struct bio meta_bio;

    /// @brief The only segment of meta_bio
    struct bio_vec meta_bvec;
};

void trn_p_rq_init(struct trn_p_rq *part,
                   struct bio *bio,
                   struct dm_context *dm_ctx,
                   enum trn_p_type type);
void trn_p_rq_end_io(struct bio *bio);

#endif
