#include <linux/slab.h>

#include "locker.h"
#include "alignment.h"
#include "macros.h"

/// @brief Allocates and initializes the lock table
/// @details
/// Expected execution context - process, may sleep.
/// @param locker Pointer to the lock table structure
/// @return 0 on success, -ENOMEM on error
int locker_init(struct locker *locker)
{
    DM_DEBUG("locker=%p\n", locker);

    locker->table = kvcalloc(LOCKER_SIZE, sizeof(*locker->table), GFP_KERNEL);
    if (!locker->table)
        return -ENOMEM;

    for (unsigned long i = 0; i < LOCKER_SIZE; i++)
    {
        spin_lock_init(&locker->table[i].wait_lock);
        INIT_LIST_HEAD(&locker->table[i].waiters);
    }

    return 0;
}

/// @brief Frees the lock table
/// @details
/// No part may hold or wait for a lock by then.
/// @param locker Pointer to the lock table
void locker_exit(struct locker *locker)
{
    DM_DEBUG("locker=%p\n", locker);

    kvfree(locker->table);
    locker->table = NULL;
}

/// @brief Finds the lock of a chunk
/// @details
/// Never fails and never allocates.
/// @param locker Lock table
/// @param index Physical sector of the start of the chunk data area
/// @return The lock of the chunk
struct lock *locker_lock_of(struct locker *locker, sector_t index)
{
    return &locker->table[(index / CHUNK_SIZE_SECTORS) & (LOCKER_SIZE - 1)];
}
