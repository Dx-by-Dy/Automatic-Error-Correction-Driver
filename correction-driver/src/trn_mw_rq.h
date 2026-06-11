#ifndef TRN_MW_RQ_H
#define TRN_MW_RQ_H

#include <linux/types.h>
#include <linux/crc64.h>
#include <linux/bio.h>

#include "alignment.h"
#include "bio_helper.h"

struct trn_p_rq;
struct trn_rq;
struct dm_context;

/// @brief Структура представления метаданных чанка
struct chunk_metadata
{
    __le64 crc[DATA_SIZE_SECTORS];
};

/// @brief Структура представления преобразования метаданных чанка при записи
struct trn_mw_rq
{
    /// @brief bio для чтения метаданных чанка.
    /// Существует только, если chunk_full == false
    struct bio *read_bio;

    /// @brief bio для записи обновленных метаданных чанка.
    struct bio *write_bio;

    /// @brief Ссылка на структуру представления преобразования чанка
    struct trn_p_rq *part;

    /// @brief Индекс первого сектора чанка запроса и количество секторов в запросе
    u8 first_sector;
    u8 nr_sectors;

    /// @brief Страница для записи метаданных чанка.
    /// Является страницей для read_bio или write_bio
    struct page *page;

    /// @brief Флаг, определяющий, что запись происходит на весь чанк
    bool chunk_full;
};

struct trn_mw_rq *
trn_mw_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx);
void complete_trn_mw_rq(struct trn_mw_rq *meta);
void trn_mw_rq_read_end_io(struct bio *bio);
void trn_mw_rq_work(struct work_struct *work);

#endif