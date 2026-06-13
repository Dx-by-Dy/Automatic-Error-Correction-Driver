#include "bio_helper.h"
#include "corrdm.h"
#include "macros.h"

/// @brief Инициализирует bio для работы с метаданными чанка
/// @details
/// Создает новый bio из bioset драйвера, привязывает его к
/// указанному сектору устройства и добавляет страницу с
/// метаданными в качестве единственного сегмента данных.
///
/// Добавляет в bio единственный сегмент длиной SECTOR_SIZE,
/// начинающийся со смещения offset внутри страницы.
///
/// При возникновении ошибки освобождает все выделенные ресурсы.
///
/// Ожидаемый контекст работы - process.
/// @param bio Адрес указателя для сохранения созданного bio
/// @param page Страница памяти, для привязки к bio
/// @param offset Смещение внутри страницы
/// @param dm_ctx Контекст драйвера
/// @param private_data Пользовательские данные для bi_private
/// @param sector Сектор метаданных для привязки к bio
/// @param opf Тип операции и дополнительные флаги используемые для bio
/// @return 0 при успехе, отрицательный код ошибки при неудаче
int metadata_bio_init(struct bio **bio,
                      struct page *page,
                      unsigned int offset,
                      struct dm_context *dm_ctx,
                      void *private_data,
                      sector_t sector,
                      blk_opf_t opf)
{
    DM_DEBUG("page=%p offset=%u sector=%llu opf=0x%x\n",
             page,
             offset,
             (unsigned long long)sector,
             opf);

    *bio = bio_alloc_bioset(dm_ctx->dev->bdev, 1, opf, GFP_NOIO, dm_ctx->transform_bs);
    if (!*bio)
    {
        DM_ERR("bio_alloc_bioset failed\n");
        return -ENOMEM;
    }

    (*bio)->bi_iter.bi_sector = sector;
    (*bio)->bi_private = private_data;

    if (bio_add_page(*bio, page, SECTOR_SIZE, offset) != SECTOR_SIZE)
    {
        DM_ERR("bio_add_page failed\n");

        bio_put(*bio);
        *bio = NULL;
        return -ENOMEM;
    }

    DM_DEBUG("bio=%p\n", *bio);

    return 0;
}
