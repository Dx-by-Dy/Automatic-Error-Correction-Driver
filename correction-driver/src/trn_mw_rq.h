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

/// @brief Представление метаданных одного чанка, хранимые на диске
/// @details
/// Располагается в секторе метаданных сразу после DATA_SIZE_SECTORS
/// секторов данных чанка. Содержит CRC64 каждого сектора данных,
/// вычисленные в порядке возрастания индекса сектора.
struct chunk_metadata
{
    /// @brief CRC64 для каждого сектора данных чанка
    __le64 crc[DATA_SIZE_SECTORS];
};

/// @brief Структура преобразования метаданных чанка при записи
/// @details
/// Создаётся при инициализации trn_p_rq при операции записи.
///
/// При частичной записи (chunk_full == false) перед записью новых
/// метаданных необходимо прочитать старые, чтобы обновить CRC только нужных
/// секторов. Для этого страница разделена на две части:
///   - [0, METADATA_SIZE_SECTORS * SECTOR_SIZE)                                                — новые метаданные (write_bio)
///   - [METADATA_SIZE_SECTORS * SECTOR_SIZE, 2 * METADATA_SIZE_SECTORS * SECTOR_SIZE)          — старые метаданные (read_bio)
///
/// При полной записи (chunk_full == true) read_bio не создаётся,
/// так как все CRC чанка вычисляются заново и write_bio отправляется напрямую.
struct trn_mw_rq
{
    /// @brief bio для чтения старых метаданных чанка с диска
    /// @details Существует только при chunk_full == false.
    struct bio *read_bio;

    /// @brief bio для записи обновлённых метаданных чанка на диск
    struct bio *write_bio;

    /// @brief Ссылка на родительскую struct trn_p_rq преобразования чанка
    struct trn_p_rq *part;

    /// @brief Индекс первого сектора данных чанка, с которого начинается trn_p_rq.
    /// Используется для вычисления соответсвующих метаданных запросу.
    u8 first_sector;

    /// @brief Количество секторов данных в trn_p_rq.
    /// Используется для вычисления соответсвующих метаданных запросу.
    u8 nr_sectors;

    /// @brief Страница памяти для хранения метаданных чанка
    /// @details При chunk_full == false страница разделена на две части:
    /// первая — новые метаданные для записи,
    /// вторая — старые метаданные прочитанные с диска.
    struct page *page;

    /// @brief Флаг полной записи чанка
    /// @details Если true — запрос покрывает все DATA_SIZE_SECTORS секторов чанка,
    /// иначе — false.
    bool chunk_full;
};

struct trn_mw_rq *
trn_mw_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx);
void complete_trn_mw_rq(struct trn_mw_rq *meta);
void update_crc_local(struct trn_mw_rq *meta);

#endif