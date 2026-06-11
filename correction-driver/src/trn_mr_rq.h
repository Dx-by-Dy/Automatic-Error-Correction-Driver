#ifndef TRN_MR_RQ_H
#define TRN_MR_RQ_H

#include <linux/types.h>
#include <linux/crc64.h>
#include <linux/bio.h>

#include "alignment.h"
#include "bio_helper.h"

struct trn_p_rq;
struct trn_rq;
struct dm_context;

/// @brief Структура представления преобразования метаданных чанка при чтении
struct trn_mr_rq
{
    /// @brief bio для чтения метаданных чанка.
    struct bio *read_bio;

    /// @brief Ссылка на структуру представления преобразования чанка
    struct trn_p_rq *part;    

    /// @brief Индекс первого сектора чанка запроса и количество секторов в запросе
    u8 first_sector;
    u8 nr_sectors;

    /// @brief Страница для записи метаданных чанка.
    /// Является страницей для read_bio
    struct page *page;
};

struct trn_mr_rq *
trn_mr_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx);
void complete_trn_mr_rq(struct trn_mr_rq *meta);
void trn_mr_rq_read_end_io(struct bio *bio);
void trn_mr_rq_work(struct work_struct *work);

#endif