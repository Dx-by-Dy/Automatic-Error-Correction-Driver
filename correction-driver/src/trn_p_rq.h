#ifndef TRN_P_RQ_H
#define TRN_P_RQ_H

#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/refcount.h>

#include "corrdm.h"
#include "locker.h"
#include "alignment.h"
#include "trn_mw_rq.h"
#include "trn_mr_rq.h"

struct trn_rq;

/// @brief Тип преобразования чанка
/// @details Определяет направление операции ввода-вывода:
/// чтение данных с последующей проверкой CRC или
/// запись данных с обновлением метаданных.
enum trn_p_type
{
    TRANSFORM_READ,
    TRANSFORM_WRITE,
};

/// @brief Состояние жизненного цикла trn_p_rq
enum trn_p_state
{
    /// @brief Структура создана, bio ещё не отправлены.
    INITIALIZED,

    /// @brief Захвачен лок чанка, bio отправлены, ожидается завершение.
    LOCKED,

    /// @brief (только при TRANSFORM_READ) Лок освобождён, выполняется
    /// проверка CRC в trn_mr_rq_work.
    CHECK_CRC
};

/// @brief Объединение указателей на структуры метаданных чтения и записи
/// @details Тип активного поля определяется полем type в trn_p_rq.
union trn_m_rq
{
    struct trn_mw_rq *write;
    struct trn_mr_rq *read;
};

/// @brief Структура преобразования одного чанка
/// @details
/// Представляет единицу обработки одного чанка в рамках родительского
/// trn_rq. Каждый trn_p_rq охватывает ровно один чанк данных.
///
/// Жизненный цикл:
///   1. trn_p_rq_init         — выделение ресурсов, инициализация bio и метаданных
///   2. submit_work           — захват лока чанка, отправка bio на устройство
///   3. trn_p_rq_end_io       — обработчик завершения bio данных и метаданных
///   4. complete_trn_p_rq     — освобождение лока, ресурсов (для TRANSFORM_READ запуск CHECK_CRC)
///   5. metadata_work         — в очереди transform_wq проверка CRC (для TRANSFORM_READ)
///                              или слияние CRC и отправка write_bio (для TRANSFORM_WRITE)
///
/// Счётчик pending отслеживает количество незавершённых bio:
/// при инициализации устанавливается в 2 (data bio + metadata bio).
/// Когда оба завершаются через trn_p_rq_end_io, вызывается complete_trn_p_rq.
struct trn_p_rq
{
    // @brief Work для захвата лока и отправки bio на устройство ниже
    struct work_struct submit_work;

    /// @brief Узел списка всех trn_p_rq в родительском trn_rq
    /// @details Валиден только до вызова trn_rq_submit.
    struct list_head list;

    /// @brief Work для обработки метаданных после завершения bio
    /// @details Для TRANSFORM_READ запускает проверку CRC (trn_mr_rq_work).
    ///          Для TRANSFORM_WRITE запускает слияние CRC и отправку write_bio (trn_mw_rq_work).
    struct work_struct metadata_work;

    /// @brief Указатель на родительский struct trn_rq
    struct trn_rq *req;

    /// @brief bio с данными чанка (без метаданных)
    struct bio *bio;

    /// @brief Индекс чанка (физический сектор начала области данных чанка)
    unsigned long index;

    /// @brief Блокировка чанка, захватываемая перед отправкой bio
    struct lock *lock;

    /// @brief Счётчик незавершённых bio: data bio + metadata bio
    /// @details Инициализируется в 2. При достижении 0 вызывается complete_trn_p_rq.
    atomic_t pending;

    /// @brief Текущее состояние жизненного цикла
    enum trn_p_state state;

    /// @brief Тип преобразования: чтение или запись
    enum trn_p_type type;

    /// @brief Структура метаданных чанка (read или write в зависимости от type)
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