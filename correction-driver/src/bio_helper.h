#ifndef BIO_HELPER_H
#define BIO_HELPER_H

#include <linux/bio.h>
#include <linux/blkdev.h>

struct trn_p_rq;

void metadata_bio_init(struct trn_p_rq *part,
                       struct page *page,
                       unsigned int offset,
                       blk_opf_t opf);

#endif
