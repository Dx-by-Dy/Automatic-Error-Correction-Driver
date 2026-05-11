#ifndef BIO_HELPER_H
#define BIO_HELPER_H

#include <linux/bio.h>
#include "write_worker.h"
#include "locker.h"

struct write_bio_part_private
{
    struct write_request *req;
    unsigned int index;
    struct lock *lock;
};

void write_orig_bio_part_end_io(struct bio *bio);
void print_bio(struct bio *bio);

#endif