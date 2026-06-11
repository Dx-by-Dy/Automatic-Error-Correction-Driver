#ifndef TRANSFORMATION_META_H
#define TRANSFORMATION_META_H

#include <linux/types.h>
#include <linux/crc64.h>
#include <linux/bio.h>

#include "alignment.h"
#include "bio_helper.h"

struct transformation_part;
struct transformation_request;
struct dm_context;

struct chunk_metadata
{
    __le64 crc[DATA_SIZE_SECTORS];
};

struct transformation_meta
{
    struct bio *read_bio;
    struct bio *write_bio;

    u8 first_sector;
    u8 nr_sectors;

    struct page *page;

    bool chunk_full;
};

struct transformation_meta *
transformation_meta_init(struct transformation_part *part,
                         struct transformation_request *req,
                         struct dm_context *dm_ctx);
void complete_meta(struct transformation_meta *meta);
void transformation_meta_read_end_io(struct bio *bio);
void metadata_work(struct work_struct *work);

#endif