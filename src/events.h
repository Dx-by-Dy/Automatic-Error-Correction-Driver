#ifndef EVENTS_H
#define EVENTS_H

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

/// @brief What waiters under a spinlock wait for
/// @details
/// The cache and the metadata cache let their waiters go the same way: whoever
/// changes something a waiter may need records an event under the lock and
/// wakes the waiters after dropping it; a waiter notes the count, drops the
/// lock and sleeps until the count changes. The lock is a spinlock, so nobody
/// sleeps holding it. Other conditions may be waited for on the same queue.
struct dcorr_events
{
    /// @brief Changes whenever waiters may go on, under the lock
    u64 count;

    /// @brief Woken when count changes
    wait_queue_head_t wait;
};

static inline void dcorr_events_init(struct dcorr_events *events)
{
    events->count = 0;
    init_waitqueue_head(&events->wait);
}

/// @brief Records that waiters may go on; the lock must be held, wake them after dropping it
static inline void dcorr_event(struct dcorr_events *events)
{
    events->count++;
}

/// @brief Waits for the next event; called with the lock held, returns with it held
static inline void dcorr_events_wait(struct dcorr_events *events, spinlock_t *lock)
{
    u64 seen = events->count;

    spin_unlock(lock);
    wait_event(events->wait, READ_ONCE(events->count) != seen);
    spin_lock(lock);
}

/// @brief Wakes the waiters, once the lock is dropped
static inline void dcorr_events_wake(struct dcorr_events *events)
{
    wake_up_all(&events->wait);
}

#endif
