#include "bio_helper.h"
#include "corrdm.h"
#include "macros.h"

/// @brief Sets up the metadata bio of a part
/// @details
/// part->meta_bio is embedded in the part, so it cannot fail to allocate. It is
/// bound to the metadata sector of the chunk, part->metadata_sector, which it
/// shares with its neighbours, with a single segment of length
/// SECTOR_SIZE at offset within page, and completes to trn_p_rq_end_io.
///
/// A bio set up before must be released with bio_uninit first.
///
/// Expected execution context - process.
/// @param part   Part whose metadata bio is set up
/// @param page   Memory page to bind to bio
/// @param offset Position within the page
/// @param opf    Operation type and additional flags for bio
void metadata_bio_init(struct trn_p_rq *part,
                       struct page *page,
                       unsigned int offset,
                       blk_opf_t opf)
{
    struct bio *bio = &part->meta_bio;

    DM_DEBUG("part=%p page=%p offset=%u opf=0x%x\n", part, page, offset, opf);

    bio_init(bio, part->dm_ctx->dev->bdev, &part->meta_bvec, 1, opf);
    bio->bi_iter.bi_sector = part->metadata_sector;
    bio->bi_end_io = trn_p_rq_end_io;
    bio->bi_private = part;
    __bio_add_page(bio, page, SECTOR_SIZE, offset);
}
