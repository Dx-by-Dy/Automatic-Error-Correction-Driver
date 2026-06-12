#include "trn_mw_rq.h"
#include "trn_p_rq.h"
#include "trn_rq.h"
#include "macros.h"

/// @brief Вычисляет CRC64 для каждого сектора bio и записывает результаты в meta->page
/// @details
/// Обходит все сегменты bio побайтово, накапливая CRC64 (big-endian)
/// для каждого сектора данных. По завершении каждого сектора записывает
/// итоговый CRC в соответствующее место meta->page, определяемый
/// индексом meta->first_sector.
/// @param meta Структура преобразования метаданных записи
/// @param bio  bio с данными для вычисления CRC
static void bio_crc_calc(struct trn_mw_rq *meta, struct bio *bio)
{
    DM_DEBUG("meta=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->first_sector, meta->nr_sectors);

    struct chunk_metadata *md = kmap_local_page(meta->page);
    unsigned int sector_idx = meta->first_sector;
    u64 current_crc = 0;
    unsigned int in_sector_pos = 0;

    struct bio_vec bvec;
    struct bvec_iter iter;
    bio_for_each_segment(bvec, bio, iter)
    {
        void *addr = kmap_local_page(bvec.bv_page);
        unsigned int bvec_pos = 0;

        while (bvec_pos < bvec.bv_len)
        {
            unsigned int len = min(bvec.bv_len - bvec_pos, SECTOR_SIZE - in_sector_pos);
            current_crc = crc64_be(current_crc, addr + bvec.bv_offset + bvec_pos, len);

            bvec_pos += len;
            in_sector_pos += len;

            if (in_sector_pos == SECTOR_SIZE)
            {
                DM_DEBUG("sector=%llu, sector_idx=%u, crc=%llx\n",
                         (unsigned long long)(meta->part->index + sector_idx), sector_idx, current_crc);

                md->crc[sector_idx++] = cpu_to_le64(current_crc);
                current_crc = 0;
                in_sector_pos = 0;
            }
        }

        kunmap_local(addr);
    }

    kunmap_local((void *)md);
    flush_dcache_page(meta->page);
}

/// @brief Инициализирует struct trn_mw_rq
/// @details
/// Выделяет память под trn_mw_rq, страницу для метаданных и необходимые bio.
///
/// При частичной записи (chunk_full == false) создаёт read_bio для чтения
/// старых метаданных во вторую часть страницы, чтобы впоследствии
/// сохранить CRC незатронутых секторов. Затем создаёт write_bio для записи
/// обновлённых метаданных из первой половины страницы.
///
/// При полной записи (chunk_full == true) read_bio не создаётся —
/// все CRC секторов пересчитываются и сразу записываются.
///
/// В обоих случаях вызывает bio_crc_calc для вычисления новых CRC
/// по данным из part->bio.
///
/// При ошибке на любом этапе освобождает все ранее выделенные ресурсы.
/// @param part   Родительская struct trn_p_rq
/// @param dm_ctx Контекст драйвера
/// @return Указатель на trn_mw_rq при успехе, NULL при ошибке
struct trn_mw_rq *
trn_mw_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx)
{
    DM_DEBUG("part=%p\n", part);

    int r;
    struct trn_mw_rq *meta;

    meta = kzalloc(sizeof(*meta), GFP_NOIO);
    if (!meta)
    {
        DM_ERR("kzalloc failed\n");
        return NULL;
    }

    meta->chunk_full = (bio_sectors(part->bio) == DATA_SIZE_SECTORS);
    meta->first_sector = (u8)(align_data_sector(part->bio->bi_iter.bi_sector) - part->index);
    meta->nr_sectors = (u8)bio_sectors(part->bio);
    meta->part = part;

    meta->page = alloc_page(GFP_NOIO);
    if (!meta->page)
    {
        DM_ERR("alloc_page failed\n");
        kfree(meta);
        return NULL;
    }

    if (!meta->chunk_full)
    {
        r = metadata_bio_init(&meta->read_bio,
                              meta->page,
                              METADATA_SIZE_SECTORS * SECTOR_SIZE,
                              dm_ctx,
                              part,
                              start_metadata_sector(part->bio->bi_iter.bi_sector),
                              (blk_opf_t)REQ_OP_READ);
        if (r)
        {
            DM_ERR("metadata_bio_init for read_bio failed, err=%d\n", r);
            __free_page(meta->page);
            kfree(meta);
            return NULL;
        }
        meta->read_bio->bi_end_io = trn_mw_rq_read_end_io;
    }

    r = metadata_bio_init(&meta->write_bio,
                          meta->page,
                          0,
                          dm_ctx,
                          part,
                          start_metadata_sector(part->bio->bi_iter.bi_sector),
                          (blk_opf_t)REQ_OP_WRITE);
    if (r)
    {
        DM_ERR("metadata_bio_init for write_bio failed, err=%d\n", r);
        if (!meta->chunk_full)
            bio_put(meta->read_bio);
        __free_page(meta->page);
        kfree(meta);
        return NULL;
    }

    meta->write_bio->bi_end_io = trn_p_rq_end_io;
    bio_crc_calc(meta, part->bio);

    DM_DEBUG("meta=%p write_bio=%p chunk_full=%d "
             "first_sector=%u nr_sectors=%u\n",
             meta, meta->write_bio, meta->chunk_full,
             meta->first_sector, meta->nr_sectors);

    return meta;
}

/// @brief Освобождает все ресурсы struct trn_mw_rq
/// @details
/// Освобождает read_bio (только при chunk_full == false), write_bio,
/// страницу памяти и саму структуру.
/// @param meta Структура преобразования метаданных
void complete_trn_mw_rq(struct trn_mw_rq *meta)
{
    DM_DEBUG("meta=%p write_bio=%p chunk_full=%d "
             "first_sector=%u nr_sectors=%u\n",
             meta, meta->write_bio, meta->chunk_full,
             meta->first_sector, meta->nr_sectors);

    if (!meta->chunk_full)
        bio_put(meta->read_bio);
    bio_put(meta->write_bio);
    __free_page(meta->page);
    kfree(meta);
}

/// @brief Обработчик завершения bio (meta->read_bio) чтения старых метаданных чанка
/// @details
/// Вызывается из контекста softirq по завершении read_bio.
///
/// При успехе запускает trn_mw_rq_work через очередь transform_wq
/// для слияния старых и новых CRC и последующей отправки write_bio.
///
/// При ошибке устанавливает флаг failed в родительском struct trn_rq
/// и декрементирует pending за write_bio, который уже не будет отправлен.
/// Если pending достигает нуля — вызывает complete_trn_p_rq.
/// @param bio Завершённый bio чтения метаданных
void trn_mw_rq_read_end_io(struct bio *bio)
{
    DM_DEBUG("bio=%p, sector=%llu\n", bio, (unsigned long long)bio->bi_iter.bi_sector);

    struct trn_p_rq *part = bio->bi_private;
    struct trn_rq *req = part->req;

    if (bio->bi_status != BLK_STS_OK)
    {
        DM_ERR("read_bio failed, bio=%p, status=%d\n", bio, bio->bi_status);

        if (!atomic_xchg(&req->failed, 1))
            req->status = bio->bi_status;

        if (atomic_dec_and_test(&part->pending))
            complete_trn_p_rq(part);

        return;
    }

    queue_work(req->dm_ctx->transform_wq, &part->metadata_work);
}

/// @brief Сливает старые и новые CRC, затем отправляет write_bio для записи на диск
/// @details
/// Запускается как work в очереди transform_wq после успешного чтения
/// старых метаданных через read_bio.
///
/// Копирует CRC секторов, не затронутых текущим запросом записи,
/// из старых метаданных (вторая часть страницы) в новые
/// (первая часть страницы). CRC затронутых секторов уже были
/// вычислены в bio_crc_calc при инициализации.
///
/// После слияния отправляет write_bio для записи обновлённых метаданных на диск.
/// @param work Указатель на work_struct, вложенный в trn_p_rq.metadata_work
void trn_mw_rq_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, metadata_work);
    struct trn_mw_rq *meta = part->meta.write;

    DM_DEBUG("part=%p first_sector=%u nr_sectors=%u\n",
             part, meta->first_sector, meta->nr_sectors);

    struct chunk_metadata *new_md = page_address(meta->page);
    struct chunk_metadata *old_md = (struct chunk_metadata *)(page_address(meta->page) + METADATA_SIZE_SECTORS * SECTOR_SIZE);

    for (int i = 0; i < DATA_SIZE_SECTORS; i++)
    {
        if (i < meta->first_sector || i >= meta->first_sector + meta->nr_sectors)
            new_md->crc[i] = old_md->crc[i];
    }

    submit_bio(meta->write_bio);
}