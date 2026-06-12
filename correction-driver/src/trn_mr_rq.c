#include "trn_mr_rq.h"
#include "trn_p_rq.h"
#include "trn_rq.h"
#include "macros.h"

/// @brief Инициализирует struct trn_mr_rq
/// @details
/// Выделяет память под trn_mr_rq, страницу для хранения метаданных
/// и создаёт bio для чтения метаданных чанка с диска.
///
/// При ошибке на любом этапе освобождает все выделенные ресурсы.
/// @param part Родительская struct trn_p_rq преобразования чанка
/// @param dm_ctx Контекст драйвера
/// @return Указатель на trn_mr_rq при успехе, NULL при ошибке
struct trn_mr_rq *
trn_mr_rq_init(struct trn_p_rq *part,
               struct dm_context *dm_ctx)
{
    DM_DEBUG("part=%p bio_sector=%llu\n", part, (unsigned long long)part->bio->bi_iter.bi_sector);

    int r;
    struct trn_mr_rq *meta;

    meta = kzalloc(sizeof(*meta), GFP_NOIO);
    if (!meta)
    {
        DM_ERR("kzalloc failed\n");
        return NULL;
    }

    meta->first_sector = (u8)(align_data_sector(part->bio->bi_iter.bi_sector) - part->index);
    meta->nr_sectors = bio_sectors(part->bio);
    meta->part = part;

    meta->page = alloc_page(GFP_NOIO);
    if (!meta->page)
    {
        DM_ERR("alloc_page failed\n");
        kfree(meta);
        return NULL;
    }

    r = metadata_bio_init(&meta->read_bio,
                          meta->page,
                          0,
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
    meta->read_bio->bi_end_io = trn_p_rq_end_io;

    DM_DEBUG("meta=%p read_bio=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->read_bio, meta->first_sector, meta->nr_sectors);

    return meta;
}

/// @brief Освобождает все ресурсы struct trn_mr_rq
/// @details
/// Освобождает bio чтения метаданных, страницу памяти и саму структуру.
/// @param meta Структура преобразования метаданных
void complete_trn_mr_rq(struct trn_mr_rq *meta)
{
    DM_DEBUG("meta=%p read_bio=%p first_sector=%u nr_sectors=%u\n",
             meta, meta->read_bio, meta->first_sector, meta->nr_sectors);

    bio_put(meta->read_bio);
    __free_page(meta->page);
    kfree(meta);
}

/// @brief Проверяет CRC прочитанных данных относительно метаданных чанка
/// @details
/// Запускается как work в очереди transform_wq после успешного завершения
/// bio чтения данных и метаданных чанка (оба завершились через trn_p_rq_end_io).
///
/// Вычисляет CRC64 побайтово по каждому сектору данных bio,
/// сравнивая результат с соответствующей записью на диске.
/// При несовпадении CRC устанавливает флаг ошибки в родительском struct trn_rq
/// и выводит ошибку в журнал.
///
/// По завершению всегда вызывает complete_trn_p_rq.
/// @param work Указатель на work_struct, вложенный в trn_p_rq.metadata_work
void trn_mr_rq_work(struct work_struct *work)
{
    struct trn_p_rq *part = container_of(work, struct trn_p_rq, metadata_work);
    struct trn_rq *req = part->req;
    struct trn_mr_rq *meta = part->meta.read;

    DM_DEBUG("part=%p req=%p first_sector=%u nr_sectors=%u\n",
             part, req, meta->first_sector, meta->nr_sectors);

    struct chunk_metadata *md = page_address(meta->page);
    unsigned int sector_idx = meta->first_sector;
    u64 current_crc = 0;
    unsigned int in_sector_pos = 0;

    struct bio_vec bvec;
    struct bvec_iter iter;

    if (atomic_read(&req->failed))
        goto out;

    bio_for_each_segment(bvec, part->bio, iter)
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
                if (md->crc[sector_idx++] != cpu_to_le64(current_crc))
                {
                    kunmap_local(addr);
                    goto error;
                }
                current_crc = 0;
                in_sector_pos = 0;
            }
        }

        kunmap_local(addr);
    }

    goto out;

error:
    DM_ERR("CRC mismatch at sector %u: on_disk=0x%llx computed=0x%llx\n",
           sector_idx - 1,
           (unsigned long long)le64_to_cpu(md->crc[sector_idx - 1]),
           (unsigned long long)current_crc);

    if (!atomic_xchg(&req->failed, 1))
        req->status = BLK_STS_IOERR;

    // Точка входа для восстановления после CRC mismatch
out:
    complete_trn_p_rq(part);
}