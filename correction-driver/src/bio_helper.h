#ifndef BIO_HELPER_H
#define BIO_HELPER_H

#include <linux/bio.h>
#include <linux/blkdev.h>

#include "locker.h"

struct dm_context;

void print_bio(struct bio *bio);
int metadata_bio_init(struct bio **bio,
                      struct page *page,
                      unsigned int offset,
                      struct dm_context *dm_ctx,
                      void *private_data,
                      sector_t sector,
                      blk_opf_t opf);

#endif