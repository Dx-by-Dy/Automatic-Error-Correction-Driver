#ifndef STATS_H
#define STATS_H

#include <linux/atomic.h>

/// @brief The counters of a device, shown by dmsetup status
/// @details
/// One place for all of them, named as in the table of "Interface" in
/// docs/en/ARCHITECTURE.md, which gives their order in dmsetup status, see
/// dcorr_status. The numbers of dirty and failed entries are not here: they are
/// states of the cache, not counters. Zeroed with the context of the target;
/// the parts of the driver count into it through a pointer.
struct dcorr_stats
{
    /// @brief Reads that waited in dcorr_map for a place among the parts in flight
    atomic64_t map_waits;

    /// @brief Writes that waited for a free entry of the cache
    atomic64_t free_waits;

    /// @brief Writes that waited for an entry under write back
    atomic64_t busy_waits;

    /// @brief Reads of the lower device that waited for the write back of their chunk
    atomic64_t read_waits;

    /// @brief Metadata areas read from the lower device
    atomic64_t metadata_loads;

    /// @brief Waits for a metadata area to be let go, as all were in use
    atomic64_t metadata_waits;

    /// @brief Sectors of the trailing copy of the metadata that failed to write
    atomic64_t trail_errors;

    /// @brief Syncs the worker made by itself, as too many metadata areas were busy, see metadata_crowded
    atomic64_t crowded_flushes;

    /// @brief Syncs before a write back of a chunk written back since the last flush, or of a chunk whose
    /// bit is clear while a clear is not yet synced, see cache_prepare_metadata
    atomic64_t barriers;

    /// @brief Chunks read to settle them, before a write back or after a read, as their two copies of the
    /// metadata differed
    atomic64_t settle_reads;

    /// @brief Sectors so read that matched neither copy, or did not read
    atomic64_t settle_mismatches;

    /// @brief Chunks read as zeros without a read of the lower device, as never written
    atomic64_t unwritten_reads;

    /// @brief Blocks of the bitmap invalid in both copies when the device was created
    atomic64_t read_only_blocks;

    /// @brief Blocks of the bitmap with one valid copy then, repaired by the next sync
    atomic64_t single_blocks;

    /// @brief Copies of the superblock of groups 2 and on that are invalid or differ
    atomic64_t bad_superblocks;

    /// @brief Copies of blocks of the bitmap that failed to write
    atomic64_t bitmap_write_errors;

    /// @brief Writes, discards and write zeroes refused in a read only range
    atomic64_t refused_writes;

    /// @brief Discards that reached the target, those covering no whole chunk among them
    atomic64_t discards;

    /// @brief Whole chunks the discards covered
    atomic64_t discarded_chunks;

    /// @brief Reads of data from the lower device that failed
    atomic64_t read_errors;

    /// @brief Sectors read from the lower device that matched neither CRC of their chunk
    atomic64_t crc_mismatches;

    /// @brief Write backs that failed, at the leading metadata sector or at the data
    atomic64_t write_errors;

    /// @brief Sectors of a copy of the metadata that failed to read, counted at each read of the area
    atomic64_t metadata_read_errors;

    /// @brief Flushes of the lower device that failed
    atomic64_t flush_errors;
};

#endif
