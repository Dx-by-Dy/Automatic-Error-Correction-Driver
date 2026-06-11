#ifndef TRANSFORMATION_PART_H
#define TRANSFORMATION_PART_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "correction-driver.h"
#include "locker.h"
#include "alignment.h"

struct transformation_request;

/// @brief Тип преобразования
enum transformation_type
{
    TRANSFORM_READ,
    TRANSFORM_WRITE,
};

/// @brief Состояние transformation_part
enum transformation_part_state
{
    INITIALIZED,
    LOCKED,
};

/// @brief Структура представления преобразования одного чанка
struct transformation_part
{
    /// @brief Работа по отправке данных на устройство ниже
    struct work_struct submit_work;

    /// @brief Список всех transformation_part.
    /// Валиден только при state == INITIALIZED
    struct list_head list;

    /// @brief Работа по обновлению метаданных и отправке на устройство ниже
    struct work_struct metadata_work;

    /// @brief Ссылка на соответствующий transformation_request
    struct transformation_request *req;

    /// @brief Bio преобразования данных (без метаданных) в чанке
    struct bio *bio;

    /// @brief Индекс чанка и соответствующий lock
    unsigned long index;
    struct lock *lock;

    /// @brief Средство синхронизации bio данных и метаданных чанка
    atomic_t pending;

    /// @brief Состояние transformation_part.
    /// Используется для правильного завершения transformation_part.
    enum transformation_part_state state;

    /// @brief Тип преобразования
    enum transformation_type type;

    /// @brief Структура представления преобразования метаданных чанка
    struct transformation_meta *meta;
};

struct transformation_part *
transformation_part_init(struct bio *part_bio,
                         struct transformation_request *req,
                         struct dm_context *dm_ctx,
                         enum transformation_type type);
void complete_part(struct transformation_part *part);

#endif