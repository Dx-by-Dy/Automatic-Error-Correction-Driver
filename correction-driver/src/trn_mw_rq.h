#ifndef TRN_MW_RQ_H
#define TRN_MW_RQ_H

#include <linux/types.h>
#include <linux/crc64.h>
#include <linux/bio.h>

#include "alignment.h"
#include "metadata.h"

struct trn_p_rq;
struct dm_context;

/// @brief Structure representing chunk metadata transformation on write
/// @details
/// Part of trn_p_rq for write operations, which only the write back of the
/// cache makes.
///
/// The CRCs of the written sectors are computed when the part is set up, and
/// go into the entry of the chunk in the metadata area in RAM only when the
/// part is submitted: the job before it on the same metadata sector may still
/// be writing that sector from the same memory. Then the metadata sector is
/// written from the area, with the entries of the neighbouring chunks and the
/// CRCs of the other sectors of this chunk as the area holds them, so nothing
/// is read first. Two writes of the same metadata sector must not be in flight
/// at once: the cache sends them one at a time.
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

    /// @brief The metadata area of the region of the chunk, held by the write back job
    struct metadata_area *area;

    /// @brief CRCs of the written sectors, at their index in the chunk
    __le64 crc[DATA_SIZE_SECTORS];
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

blk_status_t trn_mw_rq_init(struct trn_mw_rq *meta,
                            struct trn_p_rq *part,
                            struct metadata_area *area);
void update_crc_local(struct trn_mw_rq *meta);

#endif
