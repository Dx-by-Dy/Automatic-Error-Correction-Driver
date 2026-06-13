#include "corrdm.h"
#include "macros.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Smirnov");
MODULE_DESCRIPTION("DM target for Linux Kernel 6.16");

/// @brief Обрабатывает входящий bio-запрос
/// @details
/// Вызывается DM-подсистемой для каждого входящего bio.
/// Для операций чтения и записи создаёт trn_rq, который разбивает bio
/// на части по границам чанков и асинхронно обрабатывает каждую.
///
/// Для остальных операций (FLUSH, DISCARD и т.д.) переадресует bio
/// напрямую на устройство нижнего уровня.
///
/// При ошибке инициализации trn_rq входящий bio уже завершен с BLK_STS_IOERR.
/// @param ti  Таргет DM
/// @param bio Входящий bio-запрос
/// @return DM_MAPIO_SUBMITTED для READ, WRITE.
///         DM_MAPIO_REMAPPED для FLUSH, DISCARD и т.д.
static int dm_map(struct dm_target *ti, struct bio *bio)
{
    DM_DEBUG("bio=%p op=%u sector=%llu size=%u\n",
             bio,
             bio_op(bio),
             (unsigned long long)bio->bi_iter.bi_sector,
             bio->bi_iter.bi_size);

    struct trn_rq *req;
    struct dm_context *dm_ctx = ti->private;
    enum trn_p_type type;

    switch (bio_op(bio))
    {
    case REQ_OP_FLUSH:
        flush_workqueue(dm_ctx->transform_wq);
        bio->bi_iter.bi_sector = align_data_sector(bio->bi_iter.bi_sector);
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_REMAPPED;

    case REQ_OP_DISCARD:
        bio->bi_iter.bi_sector = align_data_sector(bio->bi_iter.bi_sector);
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_REMAPPED;

    case REQ_OP_READ:
        type = TRANSFORM_READ;
        break;

    case REQ_OP_WRITE:
        type = TRANSFORM_WRITE;
        break;

    default:
        DM_ERR("unsupported bio op=%u\n", bio_op(bio));
        bio->bi_iter.bi_sector = align_data_sector(bio->bi_iter.bi_sector);
        bio_set_dev(bio, dm_ctx->dev->bdev);
        return DM_MAPIO_REMAPPED;
    }

    req = trn_rq_init(bio, dm_ctx, type);
    if (!req)
    {
        DM_ERR("trn_rq_init failed, op=%u sector=%llu, type=%d\n",
               bio_op(bio),
               (unsigned long long)bio->bi_iter.bi_sector,
               type);
        return DM_MAPIO_SUBMITTED;
    }

    trn_rq_submit(req);
    return DM_MAPIO_SUBMITTED;
}

/// @brief Инициализирует DM-таргет при его создании
/// @details
/// Ожидает единственный аргумент argv[0] — путь к устройству нижнего уровня.
///
/// Последовательно выделяет и инициализирует все ресурсы:
/// таблицу блокировок, очередь работ, bioset и устройство нижнего уровня.
///
/// При ошибке на любом этапе освобождает все ранее выделенные ресурсы
/// в порядке, обратном выделению.
/// @param ti   Таргет DM
/// @param argc Количество аргументов
/// @param argv Аргументы: argv[0] — путь к устройству нижнего уровня
/// @return 0 при успехе, отрицательный код ошибки при неудаче
static int dm_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    if (argc != 1)
    {
        ti->error = "Invalid argument count: expected <device>";
        DM_ERR("expected 1 argument, got %u\n", argc);
        return -EINVAL;
    }

    DM_DEBUG("argc=%u, argv[0]=%s\n", argc, argv[0]);

    struct dm_context *dm_ctx;
    int r;

    dm_ctx = kzalloc(sizeof(*dm_ctx), GFP_KERNEL);
    if (!dm_ctx)
    {
        ti->error = "dm_context alloc failed";
        DM_ERR("kzalloc dm_context failed\n");
        return -ENOMEM;
    }

    dm_ctx->locker = kzalloc(sizeof(*dm_ctx->locker), GFP_KERNEL);
    if (!dm_ctx->locker)
    {
        ti->error = "locker alloc failed";
        DM_ERR("kzalloc locker failed\n");
        r = -ENOMEM;
        goto error_locker_alloc;
    }

    locker_init(dm_ctx->locker);

    dm_ctx->transform_wq = alloc_workqueue("transformation_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1024);
    if (!dm_ctx->transform_wq)
    {
        ti->error = "alloc_workqueue failed";
        DM_ERR("alloc_workqueue failed\n");
        r = -ENOMEM;
        goto error_alloc_workqueue;
    }

    dm_ctx->transform_bs = kzalloc(sizeof(struct bio_set), GFP_KERNEL);
    if (!dm_ctx->transform_bs)
    {
        ti->error = "bio_set alloc failed";
        DM_ERR("kzalloc bio_set failed\n");
        r = -ENOMEM;
        goto error_alloc_bioset;
    }

    r = bioset_init(dm_ctx->transform_bs, 128, 0, BIOSET_NEED_BVECS | BIOSET_NEED_RESCUER);
    if (r)
    {
        ti->error = "bioset_init failed";
        DM_ERR("bioset_init failed, err=%d\n", r);
        goto error_bioset_init;
    }

    r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &dm_ctx->dev);
    if (r)
    {
        ti->error = "dm_get_device failed";
        DM_ERR("dm_get_device failed, dev=%s err=%d\n", argv[0], r);
        goto error_dm_get_device;
    }

    ti->private = dm_ctx;
    ti->len = device_new_capacity(get_capacity(dm_ctx->dev->bdev->bd_disk));

    DM_INFO("mapped on dev=%s, disk capacity=%llu sec, available capacity=%llu sec\n",
            argv[0],
            (unsigned long long)get_capacity(dm_ctx->dev->bdev->bd_disk),
            (unsigned long long)ti->len);

    return 0;

error_dm_get_device:
    bioset_exit(dm_ctx->transform_bs);
error_bioset_init:
    kfree(dm_ctx->transform_bs);
error_alloc_bioset:
    destroy_workqueue(dm_ctx->transform_wq);
error_alloc_workqueue:
    locker_exit(dm_ctx->locker);
    kfree(dm_ctx->locker);
error_locker_alloc:
    kfree(dm_ctx);
    return r;
}

/// @brief Уничтожает DM-таргет и освобождает все ресурсы
/// @details
/// Перед уничтожением очереди работ ожидает завершения всех
/// текущих работ через flush_workqueue, чтобы гарантировать
/// отсутствие обращений к ресурсам после их освобождения.
/// @param ti Таргет DM
static void dm_dtr(struct dm_target *ti)
{
    struct dm_context *dm_ctx = ti->private;

    DM_DEBUG("dm_ctx=%p\n", dm_ctx);

    flush_workqueue(dm_ctx->transform_wq);
    destroy_workqueue(dm_ctx->transform_wq);
    locker_exit(dm_ctx->locker);
    kfree(dm_ctx->locker);
    dm_put_device(ti, dm_ctx->dev);
    bioset_exit(dm_ctx->transform_bs);
    kfree(dm_ctx->transform_bs);
    kfree(dm_ctx);
}

static struct target_type target = {
    .name = "corrdm",
    .version = {1, 0, 0},
    .module = THIS_MODULE,
    .ctr = dm_ctr,
    .dtr = dm_dtr,
    .map = dm_map,
};

/// @brief Регистрирует DM-таргет при загрузке модуля
/// @return 0 при успехе, отрицательный код ошибки при неудаче
static int __init dm_init(void)
{
    DM_DEBUG("loading\n");

    int r = dm_register_target(&target);

    if (r)
        DM_ERR("dm_register_target failed, err=%d\n", r);
    else
        DM_INFO("module loaded\n");

    return r;
}

/// @brief Точка выхода DM-таргета при выгрузке модуля
static void __exit dm_exit(void)
{
    DM_DEBUG("unloading\n");
    dm_unregister_target(&target);
    DM_INFO("module unloaded\n");
}

module_init(dm_init);
module_exit(dm_exit);
