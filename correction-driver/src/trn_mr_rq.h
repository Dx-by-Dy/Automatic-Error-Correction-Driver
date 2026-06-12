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
/// @details
/// Создаётся при инициализации trn_p_rq при операции чтения.
/// Содержит bio для чтения метаданных с диска и страницу памяти,
/// в которую будут прочитаны метаданных сектора чанка.
struct trn_mr_rq
{
    /// @brief bio для чтения метаданных чанка с диска.
    struct bio *read_bio;

    /// @brief Ссылка на родительскую struct trn_p_rq преобразования чанка
    struct trn_p_rq *part;

    /// @brief Индекс первого сектора данных чанка, с которого начинается trn_p_rq.
    /// Используется для вычисления соответсвующих метаданных запросу.
    u8 first_sector;

    /// @brief Количество секторов данных в trn_p_rq.
    /// Используется для вычисления соответсвующих метаданных запросу.
    u8 nr_sectors;

    /// @brief Страница памяти для хранения прочитанных метаданных чанка
    /// @details Используется как буфер для read_bio.
    struct page *metadata_page;

    /// @brief Сохраненный iter для bio из struct trn_p_rq
    /// @details Используется для извлечения данных из bio после его возвращения
    /// из нижнего уровня и для дальшего анализа данных и сверки CRC из metadata_page.
    /// Инициализируется родительской struct trn_p_rq при его инициализации.
    struct bvec_iter saved_iter;
};

struct trn_mr_rq *
trn_mr_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx);
void complete_trn_mr_rq(struct trn_mr_rq *meta);
void trn_mr_rq_work(struct work_struct *work);

#endif