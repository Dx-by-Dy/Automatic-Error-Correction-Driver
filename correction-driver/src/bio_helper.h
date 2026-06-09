#ifndef BIO_HELPER_H
#define BIO_HELPER_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include "locker.h"

void print_bio(struct bio *bio);

#endif