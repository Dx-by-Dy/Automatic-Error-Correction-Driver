#ifndef DCORR_MACROS_H
#define DCORR_MACROS_H

#include <linux/printk.h>
#include <linux/ratelimit.h>

#define DM_MSG_PREFIX "dcorr"

#define DM_ERR(fmt, ...) \
    pr_err("[ERROR] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

#define DM_WARN(fmt, ...) \
    pr_warn("[WARN] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

#define DM_INFO(fmt, ...) \
    pr_info("[INFO] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

struct dm_target;

/// @brief Severity of a message of a device, see dcorr_log
enum dcorr_level
{
    DCORR_LEVEL_ERR,
    DCORR_LEVEL_WARN,
    DCORR_LEVEL_INFO,
};

__printf(4, 5) void dcorr_log(struct dm_target *ti, enum dcorr_level level, const char *func, const char *fmt, ...);
void dcorr_error(struct dm_target *ti);

/*
 * Messages of a device name it as dmsetup does, see dcorr_log, so they need
 * process context and no spinlock held. Those that I/O can repeat are rate
 * limited, each place on its own, so that a failing device does not flood
 * the log; the name is looked up only for a message that is printed.
 */
#define DCORR_LOG_LIMIT(ti, level, fmt, ...)                                                    \
    do                                                                                          \
    {                                                                                           \
        static DEFINE_RATELIMIT_STATE(_rs, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST); \
        if (__ratelimit(&_rs))                                                                  \
            dcorr_log(ti, level, __func__, fmt, ##__VA_ARGS__);                                 \
    } while (0)

#define DM_DEV_ERR(ti, fmt, ...) dcorr_log(ti, DCORR_LEVEL_ERR, __func__, fmt, ##__VA_ARGS__)
#define DM_DEV_WARN(ti, fmt, ...) dcorr_log(ti, DCORR_LEVEL_WARN, __func__, fmt, ##__VA_ARGS__)
#define DM_DEV_INFO(ti, fmt, ...) dcorr_log(ti, DCORR_LEVEL_INFO, __func__, fmt, ##__VA_ARGS__)
#define DM_DEV_ERR_LIMIT(ti, fmt, ...) DCORR_LOG_LIMIT(ti, DCORR_LEVEL_ERR, fmt, ##__VA_ARGS__)
#define DM_DEV_WARN_LIMIT(ti, fmt, ...) DCORR_LOG_LIMIT(ti, DCORR_LEVEL_WARN, fmt, ##__VA_ARGS__)

/// @brief Full enable/disable of DEBUG message embedding
#ifdef DM_DEBUG_ENABLED
#define DM_DEBUG(fmt, ...) \
    pr_debug("[DEBUG] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

/// @brief Outputs the contents of a bio structure to the kernel log
/// @details
/// Used for debugging block I/O requests.
/// Outputs main bio fields and information about all
/// data segments if the request contains payload.
/// @param bio Structure bio to output
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
#define DM_DEBUG(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define DM_DEBUG_BIO(bio) ((void)(bio))
#endif

#endif
