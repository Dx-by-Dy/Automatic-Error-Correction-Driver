// SPDX-License-Identifier: GPL-2.0
/*
 * dcorrsetup: formats a device for dm-dcorr and reads its superblock.
 *
 *   dcorrsetup format [--force] DEVICE   write both copies of the superblock and empty bitmaps
 *   dcorrsetup dump DEVICE               print the superblock and the layout as key=value
 *   dcorrsetup table DEVICE              print the table line for dmsetup
 *
 * The layout comes from src/dcorr-format.h, the same code the driver uses.
 * The CRC is crc64_be of the kernel, CRC-64/ECMA-182 without reflection or a
 * final xor; the driver refuses a superblock whose CRC it computes otherwise.
 */
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dcorr-format.h"

#define CRC64_ECMA_POLY 0x42F0E1EBA9EA3693ULL
#define CRC_END (offsetof(struct dcorr_superblock, crc) + sizeof(((struct dcorr_superblock *)0)->crc))

static const char *program = "dcorrsetup";
static uint64_t crc_table[256];

static void crc64_init(void)
{
    for (unsigned int i = 0; i < 256; i++)
    {
        uint64_t crc = (uint64_t)i << 56;

        for (int bit = 0; bit < 8; bit++)
            crc = crc & (1ULL << 63) ? crc << 1 ^ CRC64_ECMA_POLY : crc << 1;
        crc_table[i] = crc;
    }
}

/// @brief crc64_be of the kernel: continues crc over len bytes of p
static uint64_t crc64_be(uint64_t crc, const void *p, size_t len)
{
    const uint8_t *bytes = p;

    while (len--)
        crc = crc_table[(crc >> 56 ^ *bytes++) & 0xff] ^ crc << 8;
    return crc;
}

/// @brief The CRC of a header, as if its field crc were zero
static uint64_t superblock_crc(const struct dcorr_superblock *sb)
{
    static const uint8_t zero[8];
    uint64_t crc = crc64_be(0, sb, offsetof(struct dcorr_superblock, crc));

    crc = crc64_be(crc, zero, sizeof(zero));
    return crc64_be(crc, (const uint8_t *)sb + CRC_END, DCORR_HEADER_BYTES - CRC_END);
}

/// @brief The CRC of a block of the bitmap, as if its field crc were zero
static uint64_t bitmap_block_crc(const struct dcorr_bitmap_block *block)
{
    static const uint8_t zero[8];
    uint64_t crc = crc64_be(0, zero, sizeof(zero));

    return crc64_be(crc, (const uint8_t *)block + sizeof(zero), DCORR_BITMAP_BLOCK_BYTES - sizeof(zero));
}

static void die(const char *format, const char *argument)
{
    fprintf(stderr, "%s: ", program);
    fprintf(stderr, format, argument);
    fputc('\n', stderr);
    exit(1);
}

static int usage(FILE *out, int code)
{
    fprintf(out,
            "Usage: %s COMMAND DEVICE\n"
            "\n"
            "Commands:\n"
            "  format [--force] DEVICE  write both copies of the superblock and empty bitmaps;\n"
            "                           --force overwrites a valid superblock\n"
            "  dump DEVICE              print the superblock and the layout as key=value\n"
            "  table DEVICE             print the table line for dmsetup\n"
            "  help                     print this help\n",
            program);
    return code;
}

/// @brief Opens the device and gives its size in sectors
/// @details A block device must have logical blocks of 512 bytes; a regular file is taken as it is.
static int open_device(const char *path, int flags, uint64_t *sectors)
{
    struct stat st;
    int fd = open(path, flags);

    if (fd < 0)
        die(errno == EBUSY ? "cannot open %s: it is in use" : "cannot open %s", path);
    if (fstat(fd, &st))
        die("cannot stat %s", path);

    if (S_ISREG(st.st_mode))
    {
        *sectors = (uint64_t)st.st_size / DCORR_SECTOR_SIZE;
        return fd;
    }
    if (!S_ISBLK(st.st_mode))
        die("%s is neither a block device nor a file", path);

    uint64_t bytes;
    int logical;

    if (ioctl(fd, BLKGETSIZE64, &bytes) || ioctl(fd, BLKSSZGET, &logical))
        die("cannot get the size of %s", path);
    if (logical != DCORR_SECTOR_SIZE)
        die("%s has logical blocks other than 512 bytes", path);
    *sectors = bytes / DCORR_SECTOR_SIZE;
    return fd;
}

/// @brief Checks a copy of the header as the driver does, see superblock_check in src/superblock.c
static const char *superblock_check(const struct dcorr_superblock *sb, unsigned int copy,
                                    const struct dcorr_layout *layout)
{
    if (memcmp(sb->magic, DCORR_MAGIC, DCORR_MAGIC_BYTES))
        return "no magic";
    if (le64toh(sb->crc) != superblock_crc(sb))
        return "CRC mismatch";
    if (le32toh(sb->version) != DCORR_VERSION)
        return "unsupported version";
    if (le32toh(sb->copy) != copy)
        return "the number of another copy";
    if (le64toh(sb->flags))
        return "unknown flags";
    if (le32toh(sb->chunk_sectors) != DCORR_CHUNK_SECTORS || le32toh(sb->region_chunks) != DCORR_REGION_CHUNKS ||
        le32toh(sb->metadata_entry_bytes) != DCORR_METADATA_ENTRY_BYTES ||
        le32toh(sb->bitmap_block_bits) != DCORR_BITMAP_BLOCK_BITS)
        return "parameters other than those of version 1";
    if (le64toh(sb->lower_sectors) != layout->lower_sectors)
        return "formatted for a device of another size";
    if (le64toh(sb->area_sectors) != layout->area_sectors || le64toh(sb->capacity) != layout->capacity ||
        le64toh(sb->regions) != layout->regions || le64toh(sb->middle_region) != layout->middle_region ||
        le64toh(sb->bitmap_blocks) != layout->bitmap_blocks)
        return "a layout other than the one computed";
    return NULL;
}

/// @brief Reads both copies; gives the valid one with the larger generation, or -1, as the driver chooses
static int read_superblock(int fd, const struct dcorr_layout *layout, struct dcorr_superblock sb[DCORR_COPIES],
                           const char *reason[DCORR_COPIES])
{
    for (unsigned int copy = 0; copy < DCORR_COPIES; copy++)
    {
        off_t offset = (off_t)(dcorr_copy_start(layout, copy) * DCORR_SECTOR_SIZE);

        if (pread(fd, &sb[copy], DCORR_HEADER_BYTES, offset) != DCORR_HEADER_BYTES)
            reason[copy] = "read failed";
        else
            reason[copy] = superblock_check(&sb[copy], copy, layout);
    }

    if (reason[0] && reason[1])
        return -1;
    if (reason[0] || reason[1])
        return reason[0] ? 1 : 0;
    return le64toh(sb[1].generation) > le64toh(sb[0].generation) ? 1 : 0;
}

static void layout_of(const char *path, uint64_t sectors, struct dcorr_layout *layout)
{
    if (dcorr_layout_compute(sectors, layout))
        die("%s is too small: it must hold two areas of the superblock and two regions of data", path);
}

static int cmd_format(const char *path, bool force)
{
    struct dcorr_superblock existing[DCORR_COPIES];
    const char *reason[DCORR_COPIES];
    struct dcorr_superblock *sb;
    struct dcorr_layout layout;
    uint64_t sectors;
    size_t area_bytes;
    uint8_t *area;
    int fd;

    fd = open_device(path, O_RDWR | O_EXCL, &sectors);
    layout_of(path, sectors, &layout);
    if (!force && read_superblock(fd, &layout, existing, reason) >= 0)
        die("%s already holds a valid superblock; --force overwrites it", path);

    area_bytes = layout.area_sectors * DCORR_SECTOR_SIZE;
    area = calloc(1, area_bytes);
    if (!area)
        die("cannot allocate %s", "an area of the superblock");

    sb = (struct dcorr_superblock *)area;
    memcpy(sb->magic, DCORR_MAGIC, DCORR_MAGIC_BYTES);
    sb->version = htole32(DCORR_VERSION);
    sb->generation = htole64(1);
    if (getrandom(sb->uuid, sizeof(sb->uuid), 0) != sizeof(sb->uuid) ||
        getrandom(sb->salt, sizeof(sb->salt), 0) != sizeof(sb->salt))
        die("cannot get random bytes for %s", "the uuid and the salt");
    sb->uuid[6] = (sb->uuid[6] & 0x0f) | 0x40; // version 4
    sb->uuid[8] = (sb->uuid[8] & 0x3f) | 0x80; // variant 1
    sb->lower_sectors = htole64(layout.lower_sectors);
    sb->capacity = htole64(layout.capacity);
    sb->chunk_sectors = htole32(DCORR_CHUNK_SECTORS);
    sb->region_chunks = htole32(DCORR_REGION_CHUNKS);
    sb->metadata_entry_bytes = htole32(DCORR_METADATA_ENTRY_BYTES);
    sb->bitmap_block_bits = htole32(DCORR_BITMAP_BLOCK_BITS);
    sb->area_sectors = htole64(layout.area_sectors);
    sb->regions = htole64(layout.regions);
    sb->middle_region = htole64(layout.middle_region);
    sb->bitmap_blocks = htole64(layout.bitmap_blocks);

    for (unsigned int copy = 0; copy < DCORR_COPIES; copy++)
    {
        off_t offset = (off_t)(dcorr_copy_start(&layout, copy) * DCORR_SECTOR_SIZE);

        sb->copy = htole32(copy);
        sb->crc = 0;
        sb->crc = htole64(superblock_crc(sb));
        for (uint64_t i = 0; i < layout.bitmap_blocks; i++)
        {
            struct dcorr_bitmap_block *block =
                (struct dcorr_bitmap_block *)(area + DCORR_HEADER_BYTES + i * DCORR_BITMAP_BLOCK_BYTES);

            block->generation = htole64(1);
            block->index = htole64(i);
            block->copy = htole32(copy);
            block->crc = htole64(bitmap_block_crc(block));
        }
        if (pwrite(fd, area, area_bytes, offset) != (ssize_t)area_bytes)
            die("cannot write the superblock to %s", path);
    }
    if (fsync(fd) || close(fd))
        die("cannot flush %s", path);
    free(area);
    return 0;
}

static void print_uuid(const uint8_t *uuid)
{
    for (int i = 0; i < 16; i++)
        printf("%s%02x", i == 4 || i == 6 || i == 8 || i == 10 ? "-" : "", uuid[i]);
}

static int cmd_dump(const char *path)
{
    struct dcorr_superblock sb[DCORR_COPIES];
    const char *reason[DCORR_COPIES];
    struct dcorr_layout layout;
    uint64_t sectors;
    int fd, chosen;

    fd = open_device(path, O_RDONLY, &sectors);
    layout_of(path, sectors, &layout);
    chosen = read_superblock(fd, &layout, sb, reason);
    close(fd);

    for (unsigned int copy = 0; copy < DCORR_COPIES; copy++)
        printf("copy%u=%s\n", copy, reason[copy] ? reason[copy] : "valid");
    printf("copy1_start=%" PRIu64 "\n", (uint64_t)dcorr_copy_start(&layout, 1));
    if (chosen < 0)
        die("%s holds no valid superblock", path);

    printf("chosen=%d\n", chosen);
    printf("version=%" PRIu32 "\n", le32toh(sb[chosen].version));
    printf("generation=%" PRIu64 "\n", le64toh(sb[chosen].generation));
    printf("flags=%" PRIu64 "\n", le64toh(sb[chosen].flags));
    printf("uuid=");
    print_uuid(sb[chosen].uuid);
    printf("\nsalt=");
    for (size_t i = 0; i < sizeof(sb[chosen].salt); i++)
        printf("%02x", sb[chosen].salt[i]);
    printf("\nlower_sectors=%" PRIu64 "\n", le64toh(sb[chosen].lower_sectors));
    printf("capacity=%" PRIu64 "\n", le64toh(sb[chosen].capacity));
    printf("chunk_sectors=%" PRIu32 "\n", le32toh(sb[chosen].chunk_sectors));
    printf("region_chunks=%" PRIu32 "\n", le32toh(sb[chosen].region_chunks));
    printf("metadata_entry_bytes=%" PRIu32 "\n", le32toh(sb[chosen].metadata_entry_bytes));
    printf("bitmap_block_bits=%" PRIu32 "\n", le32toh(sb[chosen].bitmap_block_bits));
    printf("area_sectors=%" PRIu64 "\n", le64toh(sb[chosen].area_sectors));
    printf("regions=%" PRIu64 "\n", le64toh(sb[chosen].regions));
    printf("middle_region=%" PRIu64 "\n", le64toh(sb[chosen].middle_region));
    printf("bitmap_blocks=%" PRIu64 "\n", le64toh(sb[chosen].bitmap_blocks));
    return 0;
}

static int cmd_table(const char *path)
{
    struct dcorr_superblock sb[DCORR_COPIES];
    const char *reason[DCORR_COPIES];
    struct dcorr_layout layout;
    uint64_t sectors;
    int fd, chosen;

    fd = open_device(path, O_RDONLY, &sectors);
    layout_of(path, sectors, &layout);
    chosen = read_superblock(fd, &layout, sb, reason);
    close(fd);
    if (chosen < 0)
        die("%s holds no valid superblock", path);

    printf("0 %" PRIu64 " dcorr %s\n", le64toh(sb[chosen].capacity), path);
    return 0;
}

int main(int argc, char **argv)
{
    crc64_init();

    if (argc == 2 && (!strcmp(argv[1], "help") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")))
        return usage(stdout, 0);
    if (argc == 3 && !strcmp(argv[1], "format"))
        return cmd_format(argv[2], false);
    if (argc == 4 && !strcmp(argv[1], "format") && !strcmp(argv[2], "--force"))
        return cmd_format(argv[3], true);
    if (argc == 3 && !strcmp(argv[1], "dump"))
        return cmd_dump(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "table"))
        return cmd_table(argv[2]);
    return usage(stderr, 2);
}
