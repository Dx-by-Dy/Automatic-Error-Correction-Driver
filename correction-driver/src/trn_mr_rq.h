#ifndef TRN_MR_RQ_H
#define TRN_MR_RQ_H

#include <linux/types.h>
#include <linux/crc64.h>
#include <linux/bio.h>

#include "alignment.h"
#include "bio_helper.h"

struct trn_p_rq;
struct trn_rq;
struct dm_context;

/// @brief Structure representing chunk metadata transformation on read
/// @details
/// Created during initialization of trn_p_rq for read operations.
/// Contains bio for reading metadata from disk and a memory page,
/// into which the chunk metadata sector will be read.
struct trn_mr_rq
{
    /// @brief Bio for reading chunk metadata from disk.
    struct bio *read_bio;

    /// @brief Reference to the parent struct trn_p_rq for chunk transformation
    struct trn_p_rq *part;

    /// @brief Index of the first data sector of the chunk from which trn_p_rq starts.
    /// Used to compute corresponding metadata for the request.
    u8 first_sector;

    /// @brief Number of data sectors in trn_p_rq.
    /// Used to compute corresponding metadata for the request.
    u8 nr_sectors;

    /// @brief Memory page to store read chunk metadata
    /// @details Used as a buffer for read_bio.
    struct page *metadata_page;

    /// @brief Saved iter for bio from struct trn_p_rq
    /// @details Used to extract data from bio after its return
    /// from the lower level and for further data analysis and CRC verification from metadata_page.
    /// Initialized by parent struct trn_p_rq during its initialization.
    struct bvec_iter saved_iter;
};

struct trn_mr_rq *
trn_mr_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx);
void complete_trn_mr_rq(struct trn_mr_rq *meta);
void check_crc(struct trn_mr_rq *meta);

#endif
