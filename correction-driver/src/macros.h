#define DM_MSG_PREFIX "correction-driver"

#define DM_ERR(fmt, ...) \
    pr_err("[ERROR] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

#define DM_WARN(fmt, ...) \
    pr_warn("[WARN] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

#define DM_INFO(fmt, ...) \
    pr_info("[INFO] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

/// @brief Полное включение/выключение встраивания DEBUG сообщений
#ifdef DM_DEBUG_ENABLED
#define DM_DEBUG(fmt, ...) \
    pr_debug("[DEBUG] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

/// @brief Выводит содержимое структуры bio в журнал ядра
/// @details
/// Используется для отладки запросов блочного ввода-вывода.
/// Выводит основные поля bio, а также информацию обо всех
/// сегментах данных, если запрос содержит полезную нагрузку.
/// @param bio Структура bio для вывода
#define DM_DEBUG_BIO(bio)                                                              \
    do                                                                                 \
    {                                                                                  \
        DM_DEBUG("---------------------- BIO 0x%p -----------------\n", (bio));        \
        DM_DEBUG("  bi_opf=0x%x\n", (bio)->bi_opf);                                    \
        DM_DEBUG("  bi_sector=%llu\n", (unsigned long long)(bio)->bi_iter.bi_sector);  \
        DM_DEBUG("  bi_size=%u\n", (bio)->bi_iter.bi_size);                            \
        DM_DEBUG("  bi_vcnt=%u\n", (bio)->bi_vcnt);                                    \
        DM_DEBUG("  bi_status=%d\n", (bio)->bi_status);                                \
        DM_DEBUG("  bi_max_vecs=%llu\n", (unsigned long long)(bio)->bi_max_vecs);      \
        DM_DEBUG("  bi_bdev_disk_name=%s\n", (bio)->bi_bdev->bd_disk->disk_name);      \
        if (bio_has_data(bio))                                                         \
        {                                                                              \
            struct bio_vec _bvec;                                                      \
            struct bvec_iter _iter;                                                    \
            bio_for_each_segment(_bvec, (bio), _iter)                                  \
            {                                                                          \
                DM_DEBUG("    segment: page=%p offset=%u len=%u\n",                    \
                         _bvec.bv_page,                                                \
                         _bvec.bv_offset,                                              \
                         _bvec.bv_len);                                                \
            }                                                                          \
        }                                                                              \
        DM_DEBUG("----------------------------- BIO -----------------------------\n"); \
    } while (0)

#else
#define DM_DEBUG(fmt, ...) \
    do                     \
    {                      \
    } while (0)
#define DM_DEBUG_BIO(bio) \
    do                    \
    {                     \
    } while (0)
#endif
