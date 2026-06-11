#ifndef LOCKER_H
#define LOCKER_H

#include <linux/xarray.h>
#include <linux/rwsem.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

/// @brief Таблица блокировок на основе XArray
/// @details
/// Хранит набор блокировок, индексированных по номеру чанка.
/// Блокировки создаются лениво при первом обращении и удаляются
/// автоматически при освобождении последней ссылки.
struct locker
{
    struct xarray table;
};

/// @brief Блокировка одного чанка
/// @details
/// Содержит rw_semaphore для разделения читателей и писателей,
/// счётчик ссылок для управления временем жизни и rcu_head
/// для безопасного освобождения памяти.
///
/// Жизненный цикл: lock "жив", пока refcnt > 0.
/// При обнулении refcnt объект удаляется из таблицы и
/// освобождается через RCU.
struct lock
{
    /// @brief rw_semaphore чтения-записи для защиты чанка
    struct rw_semaphore sem;

    /// @brief Счётчик ссылок для управления временем жизни
    /// @details
    /// Если refcnt == 0, lock считается мёртвым и будет удалён.
    ///
    /// Гарантируется при наличии записи в таблице struct locker, что refcnt > 0.
    refcount_t refcnt;

    /// @brief Голова RCU для отложенного освобождения памяти
    struct rcu_head rcu;
};

void locker_init(struct locker *locker);
void locker_exit(struct locker *locker);
struct lock *locker_get_lock(struct locker *locker, unsigned long index);
void locker_put_lock(struct locker *locker, unsigned long index, struct lock *lock);

#endif