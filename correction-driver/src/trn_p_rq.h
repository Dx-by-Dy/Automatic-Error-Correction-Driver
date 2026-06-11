#ifndef TRN_P_RQ_H
#define TRN_P_RQ_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "correction-driver.h"
#include "locker.h"
#include "alignment.h"
#include "trn_mw_rq.h"
#include "trn_mr_rq.h"

struct trn_rq;

/// @brief Тип преобразования
enum trn_p_type
{
    TRANSFORM_READ,
    TRANSFORM_WRITE,
};

/// @brief Состояние transformation_part
enum trn_p_state
{
    INITIALIZED,
    LOCKED,
    CHECK_CRC
};

union trn_m_rq
{
    struct trn_mw_rq *write;
    struct trn_mr_rq *read;
};

/// @brief Структура представления преобразования одного чанка
struct trn_p_rq
{
    /// @brief Работа по отправке данных на устройство ниже
    struct work_struct submit_work;

    /// @brief Список всех transformation_part.
    /// Валиден только при state == INITIALIZED
    struct list_head list;

    /// @brief Работа по обновлению метаданных и отправке на устройство ниже
    struct work_struct metadata_work;

    /// @brief Ссылка на соответствующий trn_rq
    struct trn_rq *req;

    /// @brief Bio преобразования данных (без метаданных) в чанке
    struct bio *bio;

    /// @brief Индекс чанка и соответствующий lock
    unsigned long index;
    struct lock *lock;

    /// @brief Средство синхронизации bio данных и метаданных чанка
    atomic_t pending;

    /// @brief Состояние transformation_part.
    /// Используется для правильного завершения transformation_part.
    enum trn_p_state state;

    /// @brief Тип преобразования
    enum trn_p_type type;

    /// @brief Структура представления преобразования метаданных чанка
    union trn_m_rq meta;
};

struct trn_p_rq *
trn_p_rq_init(struct bio *part_bio,
              struct trn_rq *req,
              struct dm_context *dm_ctx,
              enum trn_p_type type);
void complete_trn_p_rq(struct trn_p_rq *part);
void trn_p_rq_end_io(struct bio *bio);

#endif