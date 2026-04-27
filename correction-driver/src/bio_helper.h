#ifndef BIO_HELPER_H
#define BIO_HELPER_H

#include <linux/bio.h>

void write_orig_bio_part_end_io(struct bio *bio);
void print_bio(struct bio *bio);

#endif