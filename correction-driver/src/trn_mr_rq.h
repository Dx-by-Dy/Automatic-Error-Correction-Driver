#ifndef TRN_MR_RQ_H
#define TRN_MR_RQ_H

#include <linux/types.h>
#include <linux/crc64.h>
#include <linux/bio.h>

#include "alignment.h"
#include "metadata.h"

struct trn_p_rq;
struct dm_context;

/// @brief Structure representing chunk metadata transformation on read
/// @details
/// Part of trn_p_rq for read operations. Holds a copy of the entry of the
/// chunk, taken from the metadata cache when the read is set up.
struct trn_mr_rq
{
    /// @brief Reference to the parent struct trn_p_rq for chunk transformation
    struct trn_p_rq *part;

    /// @brief Index of the first data sector of the chunk from which trn_p_rq starts.
    /// Used to compute corresponding metadata for the request.
    u8 first_sector;

    /// @brief Number of data sectors in trn_p_rq.
    /// Used to compute corresponding metadata for the request.
    u8 nr_sectors;

    /// @brief Copy of the entry of the chunk, which the read checks the data against
    struct chunk_metadata md;

    /// @brief Saved iter for bio from struct trn_p_rq
    /// @details Used to extract data from bio after its return
    /// from the lower level and for further data analysis and CRC verification against md.
    /// Initialized by parent struct trn_p_rq during its initialization.
    struct bvec_iter saved_iter;
};

blk_status_t trn_mr_rq_init(struct trn_mr_rq *meta,
                            struct trn_p_rq *part,
                            struct dm_context *dm_ctx);
void check_crc(struct trn_mr_rq *meta);

#endif
