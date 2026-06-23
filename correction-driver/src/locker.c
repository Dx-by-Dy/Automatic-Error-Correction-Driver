#include "locker.h"
#include "macros.h"

/// @brief Initializes the lock table
/// @details
/// Performs initialization of the XArray used to store lock objects.
///
/// @param locker Pointer to the lock table structure
void locker_init(struct locker *locker)
{
    DM_DEBUG("locker=%p\n", locker);

    xa_init(&locker->table);
}

/// @brief Frees all resources of the lock table
/// @details
/// Iterates over all XArray elements and removes them via kfree_rcu.
///
/// @param locker Pointer to the lock table
void locker_exit(struct locker *locker)
{
    DM_DEBUG("locker=%p\n", locker);

    struct lock *lock;
    unsigned long index;

    xa_for_each(&locker->table, index, lock)
    {
        xa_erase(&locker->table, index);
        kfree_rcu(lock, rcu);
    }

    xa_destroy(&locker->table);
}

/// @brief Safely obtains a lock from the lock table
/// @details
/// The function attempts to obtain an existing lock from the XArray under RCU.
/// If the lock is absent, creates a new instance and attempts to atomically
/// insert it via xa_cmpxchg.
///
/// @param locker Lock table
/// @param index Lock index
/// @return Pointer to lock on success, NULL on memory allocation error
struct lock *locker_get_lock(struct locker *locker, unsigned long index)
{
    DM_DEBUG("locker=%p, index=%lu\n", locker, index);

    struct lock *lock;
    struct lock *old;

    rcu_read_lock();
    old = xa_load(&locker->table, index);
    if (old)
    {
        if (refcount_inc_not_zero(&old->refcnt))
        {
            rcu_read_unlock();
            return old;
        }
    }
    rcu_read_unlock();

    lock = kzalloc(sizeof(*lock), GFP_NOIO);
    if (!lock)
    {
        DM_ERR("kzalloc failed\n");
        return NULL;
    }
    init_rwsem(&lock->sem);
    refcount_set(&lock->refcnt, 1);

    xa_lock(&locker->table);
    old = __xa_cmpxchg(&locker->table,
                       index,
                       NULL,
                       lock,
                       GFP_NOIO);

    if (!xa_is_err(old) && old)
        refcount_inc(&old->refcnt);
    xa_unlock(&locker->table);

    if (xa_is_err(old))
    {
        DM_ERR("xa_cmpxchg failed\n");
        kfree(lock);
        return NULL;
    }

    if (old)
    {
        kfree(lock);
        return old;
    }

    return lock;
}

/// @brief Safely releases a lock from the lock table
/// @details
/// Decrements the lock's refcount. If this is the last owner,
/// the object is removed from the XArray and freed via RCU.
///
/// Guarantees safe deletion even with concurrent access.
/// @param locker Lock table
/// @param index Lock index
/// @param lock Lock
void locker_put_lock(struct locker *locker,
                     unsigned long index,
                     struct lock *lock)
{
    DM_DEBUG("locker=%p, index=%lu, lock=%p\n", locker, index, lock);

    xa_lock(&locker->table);
    if (!refcount_dec_and_test(&lock->refcnt))
    {
        xa_unlock(&locker->table);
        return;
    }

    __xa_erase(&locker->table, index);
    xa_unlock(&locker->table);

    kfree_rcu(lock, rcu);
}