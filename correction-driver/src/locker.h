#ifndef LOCKER_H
#define LOCKER_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/types.h>

/// @brief Number of locks in the table, a power of two
/// @details
/// Chunk n uses lock n modulo this, so neighbouring chunks never share a lock.
#define LOCKER_SIZE (1UL << 16)

/// @brief Lock of the chunks whose numbers are equal modulo LOCKER_SIZE
/// @details
/// Separates readers and writers of a chunk for the whole time their I/O is
/// in flight, so it is taken in one work item and released in another. A part
/// that cannot take it waits on the list, without holding a worker. The rules
/// are in chunk_lock and chunk_unlock in trn_p_rq.c.
///
/// Chunks sharing a lock sometimes wait for each other. That cannot deadlock,
/// as a part holds a single lock and does not wait for another while holding it.
struct lock
{
    /// @brief Protects readers, writer and waiters. Never held across I/O.
    spinlock_t wait_lock;

    /// @brief Number of parts holding the lock shared
    unsigned int readers;

    /// @brief A part holds the lock exclusively
    bool writer;

    /// @brief Parts waiting for the lock, in order of arrival
    struct list_head waiters;
};

/// @brief Table of chunk locks
/// @details
/// Allocated whole in dm_ctr, so taking a lock on the I/O path never allocates.
struct locker
{
    /// @brief LOCKER_SIZE locks
    struct lock *table;
};

int locker_init(struct locker *locker);
void locker_exit(struct locker *locker);
struct lock *locker_lock_of(struct locker *locker, sector_t index);

#endif
