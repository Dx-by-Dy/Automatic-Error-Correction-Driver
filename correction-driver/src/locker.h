#ifndef LOCKER_H
#define LOCKER_H

#include <linux/xarray.h>
#include <linux/rwsem.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

/// @brief Структура таблицы блокировок
struct locker
{
    struct xarray table;
};

/// @brief Структура локальной блокировки
struct lock
{
    struct rw_semaphore sem;
    refcount_t refcnt;
    struct rcu_head rcu;
};

void locker_init(struct locker *locker);
void locker_exit(struct locker *locker);
struct lock *locker_get_lock(struct locker *locker, unsigned long index);
void locker_put_lock(struct locker *locker, unsigned long index, struct lock *lock);

#endif