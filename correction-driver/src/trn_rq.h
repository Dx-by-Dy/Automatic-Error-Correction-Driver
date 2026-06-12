#ifndef TRN_RQ_H
#define TRN_RQ_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "corrdm.h"
#include "alignment.h"

struct trn_p_rq;
enum trn_p_type;

/// @brief Структура представления обработки одного bio-запроса
/// @details
/// Создаётся в dm_map для каждого входящего bio. Разбивает исходный
/// bio на части (trn_p_rq) по границам чанков и управляет их
/// жизненным циклом.
///
/// Жизненный цикл:
///   1. trn_rq_init    — разбивка bio на части, инициализация всех trn_p_rq
///   2. trn_rq_submit  — постановка всех trn_p_rq в очередь transform_wq
///   3. complete_trn_rq — вызывается когда pending достигает 0,
///                        завершает оригинальный bio и освобождает ресурсы
struct trn_rq
{
    /// @brief Контекст драйвера
    struct dm_context *dm_ctx;

    /// @brief Оригинальный bio запроса
    /// @details Захватывается через bio_get в trn_rq_init,
    /// освобождается через bio_put и завершается в complete_trn_rq.
    struct bio *orig_bio;

    /// @brief Счётчик незавершённых trn_p_rq
    /// @details Инкрементируется при добавлении каждого trn_p_rq.
    /// При достижении 0 вызывается complete_trn_rq.
    atomic_t pending;

    /// @brief Флаг наличия ошибки в любом из trn_p_rq
    /// @details Устанавливается атомарно через atomic_xchg — только
    /// первая ошибка записывается в поле status.
    atomic_t failed;

    /// @brief Итоговый статус запроса, возвращаемый в orig_bio
    blk_status_t status;

    /// @brief Список всех trn_p_rq данного запроса
    /// @details Валиден только до вызова trn_rq_submit.
    struct list_head parts;
};

struct trn_rq *
trn_rq_init(struct bio *bio,
            struct dm_context *ctx,
            enum trn_p_type type);
void trn_rq_submit(struct trn_rq *req);
void complete_trn_rq(struct trn_rq *req);

#endif