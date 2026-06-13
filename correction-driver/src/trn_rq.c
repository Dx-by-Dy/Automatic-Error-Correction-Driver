#include "trn_rq.h"
#include "macros.h"

/// @brief Завершает обработку запроса и освобождает все ресурсы
/// @details
/// Устанавливает итоговый статус в оригинальный bio, сигнализирует
/// о завершении через bio_endio и освобождает захваченную ссылку
/// через bio_put.
///
/// Вызывается когда req->pending достигает 0.
///
/// Ожидаемый контекст работы - process.
/// @param req Структура запроса
void complete_trn_rq(struct trn_rq *req)
{
    DM_DEBUG("req=%p status=%d\n", req, req->status);

    req->orig_bio->bi_status = req->status;
    bio_endio(req->orig_bio);
    bio_put(req->orig_bio);
    kfree(req);
}

/// @brief Инициализирует struct trn_rq
/// @details
/// Захватывает ссылку на orig_bio через bio_get. Итеративно разбивает
/// bio по границам чанков: если остаток bio умещается в текущий чанк —
/// клонирует его, иначе отщепляет часть через bio_split.
///
/// Для каждой части создаёт trn_p_rq, настраивает part_bio (физический
/// сектор, bi_private, bi_end_io, устройство) и добавляет в список parts.
///
/// При ошибке на любом этапе:
///   - устанавливает флаг failed
///   - завершает все уже созданные части через complete_work
///   - если ни одна часть не была создана (pending == 0) —
///     освобождает req напрямую через complete_trn_rq
///
/// Ожидаемый контекст работы - process.
/// @param orig_bio Оригинальный bio запроса
/// @param dm_ctx   Контекст драйвера
/// @param type     Тип преобразования (TRANSFORM_READ или TRANSFORM_WRITE)
/// @return Указатель на trn_rq при успехе, NULL при ошибке
struct trn_rq *
trn_rq_init(struct bio *orig_bio,
            struct dm_context *dm_ctx,
            enum trn_p_type type)
{
    DM_DEBUG("orig_bio=%p sector=%llu size=%u type=%d\n",
             orig_bio,
             (unsigned long long)orig_bio->bi_iter.bi_sector,
             orig_bio->bi_iter.bi_size,
             type);

    struct trn_rq *req;

    req = kzalloc(sizeof(*req), GFP_NOIO);
    if (!req)
    {
        DM_ERR("kzalloc failed\n");
        return NULL;
    }

    bio_get(orig_bio);
    req->dm_ctx = dm_ctx;
    req->orig_bio = orig_bio;
    atomic_set(&req->pending, 0);
    atomic_set(&req->failed, 0);
    req->status = BLK_STS_OK;
    INIT_LIST_HEAD(&req->parts);

    bool last;
    do
    {
        struct bio *part_bio;
        unsigned int len;

        len = min(sectors_until_datachunk_end(orig_bio->bi_iter.bi_sector), bio_sectors(orig_bio));
        last = (len == bio_sectors(orig_bio));

        if (last)
            part_bio = bio_alloc_clone(orig_bio->bi_bdev, orig_bio, GFP_NOIO, dm_ctx->transform_bs);
        else
            part_bio = bio_split(orig_bio, len, GFP_NOIO, dm_ctx->transform_bs);

        if (IS_ERR_OR_NULL(part_bio))
        {
            DM_ERR("bio_alloc_clone/bio_split failed\n");
            goto error;
        }

        struct trn_p_rq *part = trn_p_rq_init(part_bio, req, dm_ctx, type);
        if (!part)
        {
            DM_ERR("trn_p_rq_init failed\n");
            bio_put(part_bio);
            goto error;
        }

        part_bio->bi_iter.bi_sector = align_data_sector(part_bio->bi_iter.bi_sector);
        part_bio->bi_private = part;
        part_bio->bi_end_io = trn_p_rq_end_io;
        bio_set_dev(part_bio, dm_ctx->dev->bdev);

        DM_DEBUG("part=%p\n", part);
        DM_DEBUG_BIO(part_bio);

        list_add_tail(&part->list, &req->parts);
        atomic_inc(&req->pending);

    } while (!last);

    DM_DEBUG("req=%p parts=%d\n",
             req, atomic_read(&req->pending));

    return req;

error:
    DM_ERR("failed, cleaning up\n");

    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

    if (!atomic_read(&req->pending))
        complete_trn_rq(req);
    else
    {
        struct trn_p_rq *p;
        struct trn_p_rq *tmp;
        list_for_each_entry_safe(p, tmp, &req->parts, list)
        {
            list_del(&p->list);
            queue_work(req->dm_ctx->transform_wq, &p->complete_work);
        }
    }

    return NULL;
}

/// @brief Ставит все trn_p_rq в очередь transform_wq для обработки
/// @details
/// Обходит список parts, удаляет каждый элемент из списка и ставит
/// его submit_work в очередь transform_wq. После вызова список parts
/// становится пустым.
///
/// Ожидаемый контекст работы - process.
/// @param req Структура запроса
void trn_rq_submit(struct trn_rq *req)
{
    DM_DEBUG("req=%p, parts=%d\n", req, atomic_read(&req->pending));

    struct trn_p_rq *part;
    struct trn_p_rq *tmp;

    list_for_each_entry_safe(part, tmp, &req->parts, list)
    {
        list_del(&part->list);
        queue_work(req->dm_ctx->transform_wq, &part->submit_work);
    }
}