#ifndef TRN_P_RQ_H
#define TRN_P_RQ_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>

#include "cache.h"
#include "layout.h"
#include "trn_mw_rq.h"
#include "trn_mr_rq.h"

struct dcorr_ctx;
struct metadata_area;

/// @brief Chunk transformation type
/// @details Defines the direction of the I/O operation:
/// reading data followed by CRC verification, or
/// writing data with metadata updates.
enum trn_p_type
{
    TRANSFORM_READ,
    TRANSFORM_WRITE,
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
/// requests at chunk boundaries (ti->max_io_len), so each bio passed to dcorr_map
/// stays within one data chunk.
///
/// Lives in the per-bio data of that bio (ti->per_io_data_size), so it cannot
/// fail to allocate, and it is freed along with the bio: nothing may touch it
/// after bio_endio at the end of complete_work. Its metadata structure and
/// metadata bio are embedded in it, and the metadata comes from the metadata
/// cache, so nothing on the I/O path can fail to allocate.
///
/// A part does not keep other parts of its chunk away by itself: the cache does.
/// A read is in the tree of reads of the cache while in flight, a write back of
/// the chunk waits for it, and the write back jobs of one metadata sector go one
/// at a time.
///
/// Lifecycle:
///   1. trn_p_rq_init         — takes the metadata, sets up the bios
///   2. submit_work           — submits them to the underlying device
///   3. complete_work         — checks the CRCs of a read, completes the bio
///
/// A read submits only its data bio: its metadata is copied from RAM when it is
/// set up. A write submits the bio of its leading metadata sector with FUA, and
/// its data bio once that completes. When the metadata sector did not read, the
/// part fails without any I/O.
struct trn_p_rq
{
    /// @brief Work item for submitting bios to the underlying device
    struct work_struct submit_work;

    /// @brief Work item that finishes the part once its bios completed
    /// @details For TRANSFORM_READ: leaves the tree of reads of the cache and verifies the
    ///          CRCs (check_crc). For both: completes bio.
    struct work_struct complete_work;

    /// @brief The context of the target
    struct dcorr_ctx *dc;

    /// @brief bio containing chunk data (excluding metadata), the one passed to dcorr_map
    struct bio *bio;

    /// @brief bi_end_io of bio set by device mapper, restored to complete it
    bio_end_io_t *orig_end_io;

    /// @brief Status of the part, given to bio on completion
    /// @details Any error of the data or metadata bios, a metadata sector that did not
    /// read, or a CRC mismatch.
    blk_status_t status;

    /// @brief Logical sector where bio starts, relative to the start of the target
    sector_t sector;

    /// @brief Chunk index (physical sector of the start of the chunk data area)
    unsigned long index;

    /// @brief Physical sector that holds the metadata of the chunk, shared with its neighbours
    sector_t metadata_sector;

    /// @brief (TRANSFORM_READ only) the read in the tree of reads of the cache, see cache_read
    struct cache_lower_read lower_read;

    /// @brief (TRANSFORM_WRITE only) meta_bio completed, so submit_work sends the data
    bool meta_written;
    /// @brief (TRANSFORM_READ only) the data bio failed on the lower device
    bool read_failed;

    /// @brief Transformation type: read or write
    enum trn_p_type type;

    /// @brief Chunk metadata structure (read or write depending on type)
    union trn_m_rq meta;

    /// @brief (TRANSFORM_WRITE only) bio that writes the metadata sector of the chunk
    /// @details Set up by metadata_bio_init over the sector in the metadata area in RAM.
    struct bio meta_bio;

    /// @brief The only segment of meta_bio
    struct bio_vec meta_bvec;
};

void trn_p_rq_init(struct trn_p_rq *part,
                   struct bio *bio,
                   struct dcorr_ctx *dc,
                   enum trn_p_type type,
                   struct metadata_area *area);
void trn_p_rq_end_io(struct bio *bio);
void trn_p_rq_meta_end_io(struct bio *bio);

#endif
