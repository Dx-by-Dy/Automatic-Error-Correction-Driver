#include "locker.h"
#include "macros.h"

/// @brief Инициализирует таблицу блокировок
/// @details
/// Выполняет инициализацию XArray, используемого для хранения lock-объектов.
///
/// @param locker Указатель на структуру таблицы блокировок
void locker_init(struct locker *locker)
{
    DM_DEBUG("locker_exit: locker=%p\n", locker);

    xa_init(&locker->table);
}

/// @brief Освобождает все ресурсы таблицы блокировок
/// @details
/// Проходит по всем элементам XArray и удаляет их через kfree_rcu.
///
/// @param locker Указатель на таблицу блокировок
void locker_exit(struct locker *locker)
{
    DM_DEBUG("locker_exit: locker=%p\n", locker);

    struct lock *lock;
    unsigned long index;

    xa_for_each(&locker->table, index, lock)
    {
        xa_erase(&locker->table, index);
        kfree_rcu(lock, rcu);
    }

    xa_destroy(&locker->table);
}

/// @brief Безопасное получение лока из таблицы блокировок
/// @details
/// Функция пытается получить существующий lock из XArray под RCU.
/// Если lock отсутствует, создаёт новый экземпляр и пытается атомарно
/// вставить его через xa_cmpxchg.
///
/// @param locker Таблица блокировок
/// @param index Индекс лока
/// @return Указатель на lock при успехе, NULL при ошибке выделения памяти
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

    xa_lock_bh(&locker->table);
    old = __xa_cmpxchg(&locker->table,
                       index,
                       NULL,
                       lock,
                       GFP_NOIO);

    if (!xa_is_err(old) && old)
        refcount_inc(&old->refcnt);
    xa_unlock_bh(&locker->table);

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

/// @brief Безопасное освобождение лока из таблицы блокировок
/// @details
/// Уменьшает refcount лока. Если это последний владелец,
/// объект удаляется из XArray и освобождается через RCU.
///
/// Гарантирует безопасное удаление даже при конкурентном доступе.
/// @param locker Таблица блокировок
/// @param index Индекс лока
/// @param lock Лок
void locker_put_lock(struct locker *locker,
                     unsigned long index,
                     struct lock *lock)
{
    DM_DEBUG("locker=%p, index=%lu, lock=%p\n", locker, index, lock);

    xa_lock_bh(&locker->table);
    if (!refcount_dec_and_test(&lock->refcnt))
    {
        xa_unlock_bh(&locker->table);
        return;
    }

    __xa_erase(&locker->table, index);
    xa_unlock_bh(&locker->table);

    kfree_rcu(lock, rcu);
}