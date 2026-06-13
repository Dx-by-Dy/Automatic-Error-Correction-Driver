#include "trn_p_rq.h"
#include "macros.h"

/// @brief Захватывает лок чанка в зависимости от типа преобразования
/// @details
/// Для TRANSFORM_READ захватывает разделяемую блокировку (down_read),
/// для TRANSFORM_WRITE — эксклюзивную (down_write).
/// После захвата устанавливает состояние part->state = LOCKED.
///
/// Ожидаемый контекст работы - process.
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

/// @brief Отпускает лок чанка в зависимости от типа преобразования и состояния
/// @details
/// Отпускает блокировку только если состояние part->state == LOCKED или part->state == CRC_UPDATE.
///
/// Для TRANSFORM_READ отпускает разделяемую блокировку (up_read),
/// для TRANSFORM_WRITE — эксклюзивную (up_write).
///
/// Ожидаемый контекст работы - process.
/// @param part Структура преобразования чанка
static void unlock(struct trn_p_rq *part)
{
    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    if (part->state == LOCKED || part->state == CRC_UPDATE)
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
}

/// @brief Work-обработчик: захватывает лок чанка и отправляет bio на устройство
/// @details
/// Запускается из очереди transform_wq для каждого trn_p_rq.
///
/// Перед захватом лока проверяет флаг failed родительского
/// trn_rq — если другой чанк уже завершился с ошибкой, немедленно
/// переходит к завершению без отправки bio.
///
/// При успехе отправляет data bio и метаданные чанка в зависимости от типа преобразования:
///   - TRANSFORM_READ:  read_bio метаданных
///   - TRANSFORM_WRITE: write_bio (chunk_full) или read_bio (частичная запись)
///
/// Ожидаемый контекст работы - process.
/// @param work Указатель на work_struct, вложенный в part->submit_work
static void submit_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, submit_work);
    struct trn_rq *req = part->req;

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    if (atomic_read(&req->failed))
        goto fail;

    lock(part);

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

    queue_work(req->dm_ctx->transform_wq, &part->complete_work);
}

/// @brief Функция продвижения конечного автомата и завершения жизенного цикла структуры
/// @details
/// Вызывается когда part->pending достигает 0.
///
/// Логика завершения зависит от типа:
///
/// TRANSFORM_READ:
///   Снимает read-лок и при успешном чтении запускает check_crc
///   с последующим освобождением ресурсов.
///
/// TRANSFORM_WRITE:
///   Если chunk_full == false — обновляет CRC локально и
///   отправляет write_bio для обновления CRC на диск.
///   Переводит state в CRC_UPDATE.
///
///   Если chunk_full == true — снимает write-лок и освобождает
///   метаданные, bio, структуру и декрементирует req->pending.
///
/// Если req->pending достигает 0 — вызывает complete_trn_rq.
///
/// Ожидаемый контекст работы - process.
/// @param work Указатель на work_struct, вложенный в part->complete_work
static void complete_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, complete_work);
    struct trn_rq *req = part->req;

    DM_DEBUG("part=%p, state=%d, type=%d, index=%lu\n", part, part->state, part->type, part->index);

    switch (part->type)
    {
    case TRANSFORM_READ:
        unlock(part);
        if (part->state == LOCKED && !atomic_read(&req->failed))
            check_crc(part->meta.read);
        complete_trn_mr_rq(part->meta.read);
        break;
    case TRANSFORM_WRITE:
        if (part->state == LOCKED && !part->meta.write->chunk_full && !atomic_read(&req->failed))
        {
            part->state = CRC_UPDATE;
            update_crc_local(part->meta.write);
            atomic_inc(&part->pending);
            submit_bio(part->meta.write->write_bio);
            return;
        }
        unlock(part);
        complete_trn_mw_rq(part->meta.write);
        break;
    }

    locker_put_lock(req->dm_ctx->locker, part->index, part->lock);
    bio_put(part->bio);
    kfree(part);

    if (atomic_dec_and_test(&req->pending))
        complete_trn_rq(req);
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
/// Инициализирует save_iter поля meta для TRANSFORM_READ.
///
/// Счётчик pending инициализируется в 2: data bio + metadata bio.
///
/// Ожидаемый контекст работы - process.
///
/// При ошибке освобождает все ресурсы.
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
        part->meta.read->saved_iter = part_bio->bi_iter;
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
    INIT_WORK(&part->complete_work, complete_work);
    part->state = INITIALIZED;

    DM_DEBUG("part=%p type=%d, index=%lu\n", part, part->type, part->index);

    return part;
}

/// @brief Обработчик завершения bio данных и bio метаданных
/// @details
/// Вызывается при завершении любого bio данных или bio метаданных.
///
/// При ошибке bio фиксирует статус в родительском struct trn_rq.
///
/// Декрементирует счётчик part->pending запроса преобразования чанка.
/// Когда pending == 0, начинает complete_work для продвижения конечного автомата запроса.
///
/// Ожидаемый контекст работы - softirq.
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
        queue_work(req->dm_ctx->transform_wq, &part->complete_work);
}
