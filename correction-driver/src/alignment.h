#ifndef ALIGNMENT_H
#define ALIGNMENT_H

#include <linux/types.h>

#define DATA_SIZE_SECTORS 8
#define METADATA_SIZE_SECTORS 1
#define CHUNK_SIZE_SECTORS (DATA_SIZE_SECTORS + METADATA_SIZE_SECTORS)

#define MAX_ORIG_BIO_PARTS 16

sector_t align_data_sector(sector_t sector);
sector_t misalign_data_sector(sector_t sector);

#endif