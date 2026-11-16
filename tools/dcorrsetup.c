// SPDX-License-Identifier: GPL-2.0
/*
 * dcorrsetup: formats a device for dm-dcorr and reads its superblock.
 *
 *   dcorrsetup format [--force] [--group-size SIZE] DEVICE
 *                          write the header of every group: the superblock, empty bitmaps;
 *                          wipe where group 1 of a smaller size of a group starts
 *   dcorrsetup dump DEVICE print the superblock and the layout as key=value
 *   dcorrsetup table DEVICE
 *                          print the table line for dmsetup
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

/// @brief The copies read, as the driver reads them: those in the headers of groups 0 and 1
#define COPIES 2

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
    return crc64_be(crc, (const uint8_t *)sb + CRC_END, DCORR_SUPERBLOCK_BYTES - CRC_END);
}

/// @brief The CRC of a block of the bitmap: over the salt, then over the block as if its field crc were zero
static uint64_t bitmap_block_crc(const struct dcorr_bitmap_block *block, const uint8_t *salt)
{
    static const uint8_t zero[8];
    uint64_t crc = crc64_be(0, salt, sizeof(((struct dcorr_superblock *)0)->salt));

    crc = crc64_be(crc, zero, sizeof(zero));

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
            "  format [--force] [--group-size SIZE] DEVICE\n"
            "                           write the header of every group: the superblock and empty bitmaps;\n"
            "                           --force overwrites a valid superblock; SIZE is a power of two\n"
            "                           from 16M to 4G, 1G by default\n"
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

/// @brief Checks a copy of the superblock as the driver does, see superblock_check in src/superblock.c
static const char *superblock_check(const struct dcorr_superblock *sb, unsigned int group, uint64_t lower_sectors,
                                    uint64_t group_sectors, struct dcorr_layout *layout)
{
    uint64_t size;

    if (memcmp(sb->magic, DCORR_MAGIC, DCORR_MAGIC_BYTES))
        return "no magic";
    if (le64toh(sb->crc) != superblock_crc(sb))
        return "CRC mismatch";
    if (le32toh(sb->version) != DCORR_VERSION)
        return "unsupported version";
    if (le32toh(sb->group) != group)
        return "the number of another group";
    if (le64toh(sb->flags))
        return "unknown flags";
    if (le32toh(sb->chunk_sectors) != DCORR_CHUNK_SECTORS || le32toh(sb->region_chunks) != DCORR_REGION_CHUNKS ||
        le32toh(sb->metadata_entry_bytes) != DCORR_METADATA_ENTRY_BYTES ||
        le32toh(sb->bitmap_block_bits) != DCORR_BITMAP_BLOCK_BITS || le32toh(sb->columns) != DCORR_COLUMNS ||
        le32toh(sb->parity_columns) != DCORR_PARITY_COLUMNS ||
        le64toh(sb->header_sectors) != DCORR_GROUP_HEADER_SECTORS)
        return "parameters other than those of version 1";
    size = le64toh(sb->group_sectors);
    if (!dcorr_group_size_valid(size))
        return "a size of a group not in the list";
    if (group_sectors && size != group_sectors)
        return "a size of a group other than the one of its place";
    if (le64toh(sb->lower_sectors) != lower_sectors)
        return "formatted for a device of another size";
    if (dcorr_layout_compute(lower_sectors, size, layout))
        return "too few groups for its size of a group";
    if (le64toh(sb->capacity) != layout->capacity || le64toh(sb->groups) != layout->groups ||
        le64toh(sb->group_regions) != layout->group_regions ||
        le64toh(sb->last_group_regions) != layout->last_group_regions ||
        le64toh(sb->bitmap_blocks) != layout->bitmap_blocks)
        return "a layout other than the one computed";
    return NULL;
}

static bool read_copy(int fd, uint64_t sector, struct dcorr_superblock *sb)
{
    return pread(fd, sb, DCORR_SUPERBLOCK_BYTES, (off_t)(sector * DCORR_SECTOR_SIZE)) == DCORR_SUPERBLOCK_BYTES;
}

/// @brief Reads the copies of groups 0 and 1 as the driver does, see superblock_read in src/superblock.c
/// @return The valid one with the larger generation, or -1; layout[chosen] is its layout, start[1] where
/// the copy of group 1 was looked for last
static int read_superblock(int fd, uint64_t lower_sectors, struct dcorr_superblock sb[COPIES],
                           struct dcorr_layout layout[COPIES], const char *reason[COPIES], uint64_t start[COPIES])
{
    start[0] = 0;
    start[1] = 0;
    reason[0] = read_copy(fd, 0, &sb[0]) ? superblock_check(&sb[0], 0, lower_sectors, 0, &layout[0])
                                         : "read failed";
    if (!reason[0])
    {
        start[1] = layout[0].group_sectors;
        reason[1] = read_copy(fd, start[1], &sb[1])
                        ? superblock_check(&sb[1], 1, lower_sectors, layout[0].group_sectors, &layout[1])
                        : "read failed";
    }

    // Without group 0 the size of a group is not known: the start of group 1 is probed for each one.
    if (reason[0])
        reason[1] = "no valid copy at the start of group 1 for any size of a group";
    for (uint64_t size = DCORR_MIN_GROUP_SECTORS; reason[0] && size <= DCORR_MAX_GROUP_SECTORS; size <<= 1)
    {
        if (size + DCORR_SUPERBLOCK_SECTORS > lower_sectors)
            break;
        start[1] = size;
        if (read_copy(fd, size, &sb[1]) && !superblock_check(&sb[1], 1, lower_sectors, size, &layout[1]))
        {
            reason[1] = NULL;
            break;
        }
    }

    if (reason[0] && reason[1])
        return -1;
    if (reason[0] || reason[1])
        return reason[0] ? 1 : 0;
    return le64toh(sb[1].generation) > le64toh(sb[0].generation) ? 1 : 0;
}

/// @brief Parses the size of a group: a number of MiB with M, or of GiB with G, one of the list
static uint64_t parse_group_size(const char *text)
{
    char *end;
    unsigned long long value;
    uint64_t sectors = 0;

    errno = 0;
    value = strtoull(text, &end, 10);
    if (!errno && end != text && value && value <= DCORR_MAX_GROUP_SECTORS)
    {
        if (!strcmp(end, "M"))
            sectors = value << 11;
        else if (!strcmp(end, "G"))
            sectors = value << 21;
    }
    if (!dcorr_group_size_valid(sectors))
        die("the size of a group must be a power of two from 16M to 4G, not %s", text);
    return sectors;
}

static int cmd_format(const char *path, bool force, uint64_t group_sectors)
{
    struct dcorr_superblock existing[COPIES];
    struct dcorr_layout existing_layout[COPIES];
    const char *reason[COPIES];
    uint64_t start[COPIES];
    struct dcorr_superblock *sb;
    struct dcorr_layout layout;
    uint64_t sectors;
    size_t header_bytes;
    uint8_t *header;
    int fd;

    fd = open_device(path, O_RDWR | O_EXCL, &sectors);
    if (dcorr_layout_compute(sectors, group_sectors, &layout))
        die("%s is too small: it must hold two groups of the size given, each with two regions", path);
    if (!force && read_superblock(fd, sectors, existing, existing_layout, reason, start) >= 0)
        die("%s already holds a valid superblock; --force overwrites it", path);

    header_bytes = dcorr_header_used_sectors(&layout) * DCORR_SECTOR_SIZE;
    header = calloc(1, header_bytes);
    if (!header)
        die("cannot allocate %s", "the header of a group");

    sb = (struct dcorr_superblock *)header;
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
    sb->columns = htole32(DCORR_COLUMNS);
    sb->parity_columns = htole32(DCORR_PARITY_COLUMNS);
    sb->header_sectors = htole64(DCORR_GROUP_HEADER_SECTORS);
    sb->group_sectors = htole64(layout.group_sectors);
    sb->groups = htole64(layout.groups);
    sb->group_regions = htole64(layout.group_regions);
    sb->last_group_regions = htole64(layout.last_group_regions);
    sb->bitmap_blocks = htole64(layout.bitmap_blocks);

    for (uint64_t group = 0; group < layout.groups; group++)
    {
        off_t offset = (off_t)(dcorr_group_start(&layout, group) * DCORR_SECTOR_SIZE);

        sb->group = htole32((uint32_t)group);
        sb->crc = 0;
        sb->crc = htole64(superblock_crc(sb));
        for (uint64_t i = 0; i < 2 * layout.bitmap_blocks; i++)
        {
            struct dcorr_bitmap_block *block =
                (struct dcorr_bitmap_block *)(header + (DCORR_LEAD_BITMAP_OFFSET +
                                                        i * DCORR_BITMAP_BLOCK_SECTORS) * DCORR_SECTOR_SIZE);
            bool trail = i >= layout.bitmap_blocks;

            block->generation = htole64(1);
            block->group = htole64(trail ? (group + layout.groups - 1) % layout.groups : group);
            block->index = htole32((uint32_t)(i % layout.bitmap_blocks));
            block->role = htole32(trail ? DCORR_BITMAP_TRAIL : DCORR_BITMAP_LEAD);
            block->crc = 0;
            block->crc = htole64(bitmap_block_crc(block, sb->salt));
        }
        if (pwrite(fd, header, header_bytes, offset) != (ssize_t)header_bytes)
            die("cannot write the header of a group to %s", path);
    }

    // A copy of group 1 left by a format with smaller groups lies inside group 0, where the probe of the
    // driver would take it with group 0 damaged. The larger sizes start groups of this format, written above.
    static const uint8_t wipe[DCORR_SUPERBLOCK_BYTES];

    for (uint64_t size = DCORR_MIN_GROUP_SECTORS; size < layout.group_sectors; size <<= 1)
    {
        if (pwrite(fd, wipe, sizeof(wipe), (off_t)(size * DCORR_SECTOR_SIZE)) != (ssize_t)sizeof(wipe))
            die("cannot wipe an old copy of the superblock on %s", path);
    }
    if (fsync(fd) || close(fd))
        die("cannot flush %s", path);
    free(header);
    return 0;
}

static void print_uuid(const uint8_t *uuid)
{
    for (int i = 0; i < 16; i++)
        printf("%s%02x", i == 4 || i == 6 || i == 8 || i == 10 ? "-" : "", uuid[i]);
}

static int cmd_dump(const char *path)
{
    struct dcorr_superblock sb[COPIES];
    struct dcorr_layout layout[COPIES];
    const char *reason[COPIES];
    uint64_t start[COPIES];
    uint64_t sectors;
    int fd, chosen;

    fd = open_device(path, O_RDONLY, &sectors);
    chosen = read_superblock(fd, sectors, sb, layout, reason, start);
    close(fd);

    for (unsigned int copy = 0; copy < COPIES; copy++)
        printf("group%u=%s\n", copy, reason[copy] ? reason[copy] : "valid");
    printf("group1_start=%" PRIu64 "\n", start[1]);
    if (chosen < 0)
        die("%s holds no valid superblock", path);

    const struct dcorr_superblock *c = &sb[chosen];

    printf("chosen=%d\n", chosen);
    printf("version=%" PRIu32 "\n", le32toh(c->version));
    printf("generation=%" PRIu64 "\n", le64toh(c->generation));
    printf("flags=%" PRIu64 "\n", le64toh(c->flags));
    printf("uuid=");
    print_uuid(c->uuid);
    printf("\nsalt=");
    for (size_t i = 0; i < sizeof(c->salt); i++)
        printf("%02x", c->salt[i]);
    printf("\nlower_sectors=%" PRIu64 "\n", le64toh(c->lower_sectors));
    printf("capacity=%" PRIu64 "\n", le64toh(c->capacity));
    printf("chunk_sectors=%" PRIu32 "\n", le32toh(c->chunk_sectors));
    printf("region_chunks=%" PRIu32 "\n", le32toh(c->region_chunks));
    printf("metadata_entry_bytes=%" PRIu32 "\n", le32toh(c->metadata_entry_bytes));
    printf("bitmap_block_bits=%" PRIu32 "\n", le32toh(c->bitmap_block_bits));
    printf("columns=%" PRIu32 "\n", le32toh(c->columns));
    printf("parity_columns=%" PRIu32 "\n", le32toh(c->parity_columns));
    printf("header_sectors=%" PRIu64 "\n", le64toh(c->header_sectors));
    printf("group_sectors=%" PRIu64 "\n", le64toh(c->group_sectors));
    printf("groups=%" PRIu64 "\n", le64toh(c->groups));
    printf("group_regions=%" PRIu64 "\n", le64toh(c->group_regions));
    printf("last_group_regions=%" PRIu64 "\n", le64toh(c->last_group_regions));
    printf("bitmap_blocks=%" PRIu64 "\n", le64toh(c->bitmap_blocks));
    return 0;
}

static int cmd_table(const char *path)
{
    struct dcorr_superblock sb[COPIES];
    struct dcorr_layout layout[COPIES];
    const char *reason[COPIES];
    uint64_t start[COPIES];
    uint64_t sectors;
    int fd, chosen;

    fd = open_device(path, O_RDONLY, &sectors);
    chosen = read_superblock(fd, sectors, sb, layout, reason, start);
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
    if (argc >= 3 && !strcmp(argv[1], "format"))
    {
        uint64_t group_sectors = DCORR_DEFAULT_GROUP_SECTORS;
        bool force = false;
        int i;

        for (i = 2; i < argc - 1; i++)
        {
            if (!strcmp(argv[i], "--force"))
                force = true;
            else if (!strcmp(argv[i], "--group-size") && i + 2 < argc)
                group_sectors = parse_group_size(argv[++i]);
            else
                return usage(stderr, 2);
        }
        return cmd_format(argv[argc - 1], force, group_sectors);
    }
    if (argc == 3 && !strcmp(argv[1], "dump"))
        return cmd_dump(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "table"))
        return cmd_table(argv[2]);
    return usage(stderr, 2);
}
