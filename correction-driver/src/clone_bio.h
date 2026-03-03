#ifndef CLONE_BIO_H
#define CLONE_BIO_H

struct bio *clone_bio(struct bio *orig, struct block_device *bdev);
void clone_end_io(struct bio *clone);
void print_bio(struct bio *bio);

#endif