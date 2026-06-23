#ifndef TRN_RQ_H
#define TRN_RQ_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "corrdm.h"
#include "alignment.h"

struct trn_p_rq;
enum trn_p_type;

/// @brief Structure representing the processing of a single bio request
/// @details
/// Created in dm_map for each incoming bio. Splits the original
/// bio into parts (trn_p_rq) along chunk boundaries and manages
/// their lifecycle.
///
/// Lifecycle:
///   1. trn_rq_init     — splitting bio into parts, initializing all trn_p_rq instances
///   2. trn_rq_submit   — queuing all trn_p_rq instances into transform_wq
///   3. complete_trn_rq — invoked when pending reaches 0,
///                        completes the original bio and releases resources
struct trn_rq
{
    /// @brief Driver context
    struct dm_context *dm_ctx;

    /// @brief Original request bio
    /// @details Acquired via bio_get in trn_rq_init,
    /// released via bio_put and completed in complete_trn_rq.
    struct bio *orig_bio;

    /// @brief Counter of outstanding trn_p_rq instances
    /// @details Incremented when adding each trn_p_rq.
    /// When it reaches 0, complete_trn_rq is invoked.
    atomic_t pending;

    /// @brief Flag indicating if an error occurred in any trn_p_rq
    /// @details Set atomically via atomic_xchg — only
    /// the first encountered error is recorded into the status field.
    atomic_t failed;

    /// @brief Final status of the request returned to orig_bio
    blk_status_t status;

    /// @brief List of all trn_p_rq instances for this request
    /// @details Valid only until trn_rq_submit is called.
    struct list_head parts;
};

struct trn_rq *
trn_rq_init(struct bio *bio,
            struct dm_context *ctx,
            enum trn_p_type type);
void trn_rq_submit(struct trn_rq *req);
void complete_trn_rq(struct trn_rq *req);

#endif