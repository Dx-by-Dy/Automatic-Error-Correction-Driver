#ifndef LOCKER_H
#define LOCKER_H

#include <linux/xarray.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

/// @brief Lock table based on XArray
/// @details
/// Stores a set of locks indexed by chunk number.
/// Locks are created lazily on first access and deleted
/// automatically when the last reference is released.
struct locker
{
    struct xarray table;
};

/// @brief Lock for a single chunk
/// @details
/// Separates readers and writers of a chunk for the whole time their I/O is
/// in flight, so it is taken in one work item and released in another. A part
/// that cannot take it waits on the list, without holding a worker. The rules
/// are in chunk_lock and chunk_unlock in trn_p_rq.c.
///
/// Lifetime: lock is "alive" as long as refcnt > 0.
/// When refcnt reaches zero, the object is removed from the table and
/// freed via RCU.
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

    /// @brief Reference counter for lifetime management
    /// @details
    /// If refcnt == 0, the lock is considered dead and will be deleted.
    ///
    /// It is guaranteed that while present in struct locker, refcnt > 0.
    refcount_t refcnt;

    /// @brief RCU head for deferred memory release
    struct rcu_head rcu;
};

void locker_init(struct locker *locker);
void locker_exit(struct locker *locker);
struct lock *locker_get_lock(struct locker *locker, unsigned long index);
void locker_put_lock(struct locker *locker, unsigned long index, struct lock *lock);

#endif
