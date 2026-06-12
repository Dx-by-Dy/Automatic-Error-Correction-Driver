#include "trn_p_rq.h"
#include "macros.h"

/// @brief Захватывает лок чанка в зависимости от типа преобразования
/// @details
/// Для TRANSFORM_READ захватывает разделяемую блокировку (down_read),
/// для TRANSFORM_WRITE — эксклюзивную (down_write).
/// После захвата устанавливает состояние part->state = LOCKED.
/// @param part Структура преобразования чанка
static void lock(struct trn_p_rq *part)
{
    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    switch (part->type)
    {
    case TRANSFORM_READ:
        down_read(&part->lock->sem);
        break;
    case TRANSFORM_WRITE:
        down_write(&part->lock->sem);
        break;
    }

    part->state = LOCKED;
}

/// @brief Work-обработчик: захватывает лок чанка и отправляет bio на устройство
/// @details
/// Запускается из очереди transform_wq для каждого trn_p_rq.
///
/// Перед захватом лока и после него проверяет флаг failed родительского
/// trn_rq — если другой чанк уже завершился с ошибкой, немедленно
/// переходит к завершению без отправки bio.
///
/// При успехе отправляет data bio и метаданные чанка в зависимости от типа преобразования:
///   - TRANSFORM_READ:  read_bio метаданных
///   - TRANSFORM_WRITE: write_bio (chunk_full) или read_bio (частичная запись)
///
/// При ошибке вызывает complete_trn_p_rq.
/// @param work Указатель на work_struct, вложенный в trn_p_rq.submit_work
static void submit_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, submit_work);
    struct trn_rq *req = part->req;

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    if (atomic_read(&req->failed))
        goto fail;

    lock(part);

    if (atomic_read(&req->failed))
        goto fail;

    switch (part->type)
    {
    case TRANSFORM_READ:
        submit_bio(part->meta.read->read_bio);
        break;
    case TRANSFORM_WRITE:
        if (part->meta.write->chunk_full)
            submit_bio(part->meta.write->write_bio);
        else
            submit_bio(part->meta.write->read_bio);
        break;
    }

    submit_bio(part->bio);

    return;

fail:
    DM_ERR("req failed before submission, part=%p, index=%lu, status=%d\n", part, part->index, req->status);

    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

    complete_trn_p_rq(part);
}

/// @brief Инициализирует struct trn_p_rq
/// @details
/// Выделяет память под trn_p_rq, инициализирует поля и создаёт
/// структуру метаданных (trn_mr_rq или trn_mw_rq) в зависимости
/// от типа преобразования.
///
/// Получает лок чанка через locker_get_lock по индексу начала
/// области данных чанка.
///
/// При ошибке освобождает все ресурсы.
///
/// Счётчик pending инициализируется в 2: data bio + metadata bio.
/// @param part_bio bio с данными чанка
/// @param req      Родительский struct trn_rq
/// @param dm_ctx   Контекст драйвера
/// @param type     Тип преобразования (TRANSFORM_READ или TRANSFORM_WRITE)
/// @return Указатель на trn_p_rq при успехе, NULL при ошибке
struct trn_p_rq *
trn_p_rq_init(struct bio *part_bio,
              struct trn_rq *req,
              struct dm_context *dm_ctx,
              enum trn_p_type type)
{
    DM_DEBUG("part_bio=%p, req=%p, type=%d\n", part_bio, req, type);

    struct trn_p_rq *part;

    part = kzalloc(sizeof(*part), GFP_NOIO);
    if (!part)
    {
        DM_ERR("kzalloc failed\n");
        return NULL;
    }

    part->index = start_data_sector(part_bio->bi_iter.bi_sector);
    part->req = req;
    part->bio = part_bio;
    part->type = type;
    atomic_set(&part->pending, 2);

    switch (part->type)
    {
    case TRANSFORM_READ:
        part->meta.read = trn_mr_rq_init(part, dm_ctx);
        if (!part->meta.read)
        {
            DM_ERR("trn_mr_rq_init failed\n");
            kfree(part);
            return NULL;
        }
        break;
    case TRANSFORM_WRITE:
        part->meta.write = trn_mw_rq_init(part, dm_ctx);
        if (!part->meta.write)
        {
            DM_ERR("trn_mw_rq_init failed\n");
            kfree(part);
            return NULL;
        }
        break;
    }

    part->lock = locker_get_lock(dm_ctx->locker, part->index);
    if (!part->lock)
    {
        DM_ERR("locker_get_lock failed\n");
        switch (part->type)
        {
        case TRANSFORM_READ:
            complete_trn_mr_rq(part->meta.read);
            break;
        case TRANSFORM_WRITE:
            complete_trn_mw_rq(part->meta.write);
            break;
        }
        kfree(part);
        return NULL;
    }

    INIT_WORK(&part->submit_work, submit_work);
    switch (part->type)
    {
    case TRANSFORM_READ:
        INIT_WORK(&part->metadata_work, trn_mr_rq_work);
        break;
    case TRANSFORM_WRITE:
        INIT_WORK(&part->metadata_work, trn_mw_rq_work);
        break;
    }
    part->state = INITIALIZED;

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    return part;
}

/// @brief Завершает обработку чанка и освобождает все ресурсы
/// @details
/// Вызывается когда оба bio (data + metadata) завершились, либо
/// при ошибке до отправки bio.
///
/// Логика завершения зависит от состояния и типа:
///
/// LOCKED + TRANSFORM_READ:
///   Снимает read-лок, переводит состояние в CHECK_CRC и запускает
///   trn_mr_rq_work для проверки CRC. Функция возвращается — ресурсы
///   будут освобождены после завершения work.
///
/// LOCKED + TRANSFORM_WRITE:
///   Снимает write-лок, освобождает метаданные, bio, структуру
///   и декрементирует req->pending.
///
/// INITIALIZED / CHECK_CRC (любой тип):
///   Освобождает метаданные, bio, структуру и декрементирует req->pending.
///
/// Если req->pending достигает 0 — вызывает complete_trn_rq.
/// @param part Структура преобразования чанка
void complete_trn_p_rq(struct trn_p_rq *part)
{
    DM_DEBUG("part=%p, state=%d, type=%d, index=%lu\n", part, part->state, part->type, part->index);

    struct trn_rq *req = part->req;

    if (part->state == LOCKED)
    {
        switch (part->type)
        {
        case TRANSFORM_READ:
            up_read(&part->lock->sem);
            break;
        case TRANSFORM_WRITE:
            up_write(&part->lock->sem);
            break;
        }
    }

    switch (part->type)
    {
    case TRANSFORM_READ:
        if (part->state == LOCKED)
        {
            part->state = CHECK_CRC;
            queue_work(req->dm_ctx->transform_wq, &part->metadata_work);
            return;
        }
        complete_trn_mr_rq(part->meta.read);
        break;
    case TRANSFORM_WRITE:
        complete_trn_mw_rq(part->meta.write);
        break;
    }

    locker_put_lock(req->dm_ctx->locker, part->index, part->lock);
    bio_put(part->bio);
    kfree(part);

    if (atomic_dec_and_test(&req->pending))
        complete_trn_rq(req);
}

/// @brief Обработчик завершения bio данных и bio метаданных
/// @details
/// Вызывается из softirq-контекста при завершении part->bio (data)
/// или write_bio (для TRANSFORM_TWRITE) / read_bio (для TRANSFORM_READ) метаданных.
///
/// При ошибке bio фиксирует статус в родительском struct trn_rq.
///
/// Декрементирует счётчик pending. Когда оба bio завершены (pending == 0),
/// вызывает complete_trn_p_rq для продвижения конечного автомата.
/// @param bio Завершённый bio
void trn_p_rq_end_io(struct bio *bio)
{
    struct trn_p_rq *part = bio->bi_private;
    struct trn_rq *req = part->req;

    DM_DEBUG("bio=%p, status=%d, sector=%llu\n", bio, bio->bi_status, (unsigned long long)bio->bi_iter.bi_sector);

    if (bio->bi_status != BLK_STS_OK)
    {
        DM_ERR("bio failed, bio=%p, status=%d, sector=%llu\n", bio, bio->bi_status, (unsigned long long)bio->bi_iter.bi_sector);

        if (!atomic_xchg(&req->failed, 1))
            req->status = bio->bi_status;
    }

    if (atomic_dec_and_test(&part->pending))
        complete_trn_p_rq(part);
}