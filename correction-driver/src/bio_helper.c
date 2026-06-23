#include "bio_helper.h"
#include "corrdm.h"
#include "macros.h"

/// @brief Initializes bio for working with chunk metadata
/// @details
/// Creates a new bio from the driver's bioset, binds it to
/// the specified device sector, and adds a page with metadata
/// as the only data segment.
///
/// Adds a single segment of length SECTOR_SIZE to the bio,
/// starting at offset within the page.
///
/// If an error occurs, frees all allocated resources.
///
/// Expected execution context - process.
/// @param bio Pointer to store the created bio
/// @param page Memory page to bind to bio
/// @param offset Offset within the page
/// @param dm_ctx Driver context
/// @param private_data User data for bi_private
/// @param sector Metadata sector to bind to bio
/// @param opf Operation type and additional flags for bio
/// @return 0 on success, negative error code on failure
int metadata_bio_init(struct bio **bio,
                      struct page *page,
                      unsigned int offset,
                      struct dm_context *dm_ctx,
                      void *private_data,
                      sector_t sector,
                      blk_opf_t opf)
{
    DM_DEBUG("page=%p offset=%u sector=%llu opf=0x%x\n",
             page,
             offset,
             (unsigned long long)sector,
             opf);

    *bio = bio_alloc_bioset(dm_ctx->dev->bdev, 1, opf, GFP_NOIO, dm_ctx->transform_bs);
    if (!*bio)
    {
        DM_ERR("bio_alloc_bioset failed\n");
        return -ENOMEM;
    }

    (*bio)->bi_iter.bi_sector = sector;
    (*bio)->bi_private = private_data;

    if (bio_add_page(*bio, page, SECTOR_SIZE, offset) != SECTOR_SIZE)
    {
        DM_ERR("bio_add_page failed\n");

        bio_put(*bio);
        *bio = NULL;
        return -ENOMEM;
    }

    DM_DEBUG("bio=%p\n", *bio);

    return 0;
}
