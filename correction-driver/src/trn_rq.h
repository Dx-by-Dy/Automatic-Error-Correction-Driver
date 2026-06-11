#ifndef TRN_RQ_H
#define TRN_RQ_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "correction-driver.h"
#include "locker.h"
#include "alignment.h"

struct trn_p_rq;
enum trn_p_type;

/// @brief Cтруктура представления обработки запроса
struct trn_rq
{
    /// @brief Контекст драйвера
    struct dm_context *dm_ctx;

    /// @brief Оригинальный bio запроса
    struct bio *orig_bio;

    /// @brief Средство синхронизации всех trn_p_rq
    atomic_t pending;

    /// @brief Средство синхронизации ошибок всех trn_p_rq
    atomic_t failed;

    /// @brief Статус всего запроса
    blk_status_t status;

    /// @brief Список всех trn_p_rq.
    /// Валиден только до trn_rq_submit
    struct list_head parts;
};

struct trn_rq *
trn_rq_init(struct bio *bio,
            struct dm_context *ctx,
            enum trn_p_type type);
void complete_trn_rq(struct trn_rq *req);
void trn_rq_submit(struct trn_rq *req);

#endif