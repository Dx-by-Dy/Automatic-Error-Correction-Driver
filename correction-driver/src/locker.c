#include "locker.h"

void locker_init(struct locker *locker)
{
    xa_init(&locker->table);
}

void locker_exit(struct locker *locker)
{
    struct lock *lock;
    unsigned long index;

    xa_for_each(&locker->table, index, lock)
    {
        xa_erase(&locker->table, index);
        kfree(lock);
    }

    xa_destroy(&locker->table);
}

/// @brief Безопасное получение лока из таблицы блокировок
/// @param locker Таблица блокировок
/// @param index Индекс лока
/// @return Лок - если все успешно, NULL - если произошла ошибка xa_cmpxchg
struct lock *locker_get_lock(struct locker *locker, unsigned long index)
{
    struct lock *lock;
    struct lock *old;

retry:

    // Пытаемся получить существующий лок
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

    // Создаем новый лок
    lock = kzalloc(sizeof(*lock), GFP_KERNEL);
    if (!lock)
        return NULL;
    init_rwsem(&lock->sem);
    refcount_set(&lock->refcnt, 1);

    // Пробуем атомарную вставку если нет лока
    old = xa_cmpxchg(&locker->table,
                     index,
                     NULL,
                     lock,
                     GFP_KERNEL);

    // Если ошибка, то выходим
    // TODO: Возможно стоит делать retry?
    if (xa_is_err(old))
    {
        kfree(lock);
        return NULL;
    }

    // Успешная вставка
    if (!old)
        return lock;

    // Вставка не удалась, удаляем лок
    kfree(lock);

    // На нашем месте существует живой лок
    if (refcount_inc_not_zero(&old->refcnt))
        return old;

    // На нашем месте есть не живой лок, который сейчас удаляется,
    // поэтому пробуем еще раз
    goto retry;
}

/// @brief Безопасное освобождение лока из таблицы блокировок
/// @param locker Таблица блокировок
/// @param index Индекс лока
/// @param lock Лок
void locker_put_lock(struct locker *locker,
                     unsigned long index,
                     struct lock *lock)
{
    // Полученный лок все еще живой
    if (!refcount_dec_and_test(&lock->refcnt))
        return;

    // Удаляем лок из таблицы
    xa_erase(&locker->table, index);

    // Удаляем лок, когда это безопасно
    kfree_rcu(lock, rcu);
}