#ifndef LOCKER_H
#define LOCKER_H

#include <linux/xarray.h>
#include <linux/rwsem.h>
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
/// Contains rw_semaphore for separating readers and writers,
/// reference counter for lifetime management, and rcu_head
/// for safe memory deallocation.
///
/// Lifetime: lock is "alive" as long as refcnt > 0.
/// When refcnt reaches zero, the object is removed from the table and
/// freed via RCU.
struct lock
{
    /// @brief Read-write semaphore for protecting the chunk
    struct rw_semaphore sem;
 
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