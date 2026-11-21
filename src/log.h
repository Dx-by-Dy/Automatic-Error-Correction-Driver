#ifndef LOG_H
#define LOG_H

#include <linux/printk.h>
#include <linux/ratelimit.h>

/*
 * The messages of the driver, and the event of the first error of a device.
 * Messages of the module name no device; those of a device name it as dmsetup
 * does. Only debug messages name the function they come from, so that dynamic
 * debug can be turned on for one place.
 */

#define DM_MSG_PREFIX "dcorr"

#define DCORR_ERR(fmt, ...) pr_err("[ERROR] " DM_MSG_PREFIX ": " fmt, ##__VA_ARGS__)
#define DCORR_WARN(fmt, ...) pr_warn("[WARN] " DM_MSG_PREFIX ": " fmt, ##__VA_ARGS__)
#define DCORR_INFO(fmt, ...) pr_info("[INFO] " DM_MSG_PREFIX ": " fmt, ##__VA_ARGS__)

struct dm_target;
struct work_struct;

/// @brief Severity of a message of a device, see dcorr_log
enum dcorr_level
{
    DCORR_LEVEL_ERR,
    DCORR_LEVEL_WARN,
    DCORR_LEVEL_INFO,
};

__printf(3, 4) void dcorr_log(struct dm_target *ti, enum dcorr_level level, const char *fmt, ...);
void dcorr_error(struct dm_target *ti);
void dcorr_event_work(struct work_struct *work);

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
            dcorr_log(ti, level, fmt, ##__VA_ARGS__);                                           \
    } while (0)

#define DCORR_DEV_ERR(ti, fmt, ...) dcorr_log(ti, DCORR_LEVEL_ERR, fmt, ##__VA_ARGS__)
#define DCORR_DEV_WARN(ti, fmt, ...) dcorr_log(ti, DCORR_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define DCORR_DEV_INFO(ti, fmt, ...) dcorr_log(ti, DCORR_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define DCORR_DEV_ERR_LIMIT(ti, fmt, ...) DCORR_LOG_LIMIT(ti, DCORR_LEVEL_ERR, fmt, ##__VA_ARGS__)
#define DCORR_DEV_WARN_LIMIT(ti, fmt, ...) DCORR_LOG_LIMIT(ti, DCORR_LEVEL_WARN, fmt, ##__VA_ARGS__)

/// @brief Full enable/disable of DEBUG message embedding
#ifdef DCORR_DEBUG_ENABLED
#define DCORR_DEBUG(fmt, ...) \
    pr_debug("[DEBUG] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

/// @brief Outputs the contents of a bio structure to the kernel log
/// @details
/// Used for debugging block I/O requests.
/// Outputs main bio fields and information about all
/// data segments if the request contains payload.
/// @param bio Structure bio to output
#define DCORR_DEBUG_BIO(bio)                                                              \
    do                                                                                    \
    {                                                                                     \
        DCORR_DEBUG("---------------------- BIO 0x%p -----------------\n", (bio));        \
        DCORR_DEBUG("  bi_opf=0x%x\n", (bio)->bi_opf);                                    \
        DCORR_DEBUG("  bi_sector=%llu\n", (unsigned long long)(bio)->bi_iter.bi_sector);  \
        DCORR_DEBUG("  bi_size=%u\n", (bio)->bi_iter.bi_size);                            \
        DCORR_DEBUG("  bi_vcnt=%u\n", (bio)->bi_vcnt);                                    \
        DCORR_DEBUG("  bi_status=%d\n", (bio)->bi_status);                                \
        DCORR_DEBUG("  bi_max_vecs=%llu\n", (unsigned long long)(bio)->bi_max_vecs);      \
        DCORR_DEBUG("  bi_bdev_disk_name=%s\n", (bio)->bi_bdev->bd_disk->disk_name);      \
        if (bio_has_data(bio))                                                            \
        {                                                                                 \
            struct bio_vec _bvec;                                                         \
            struct bvec_iter _iter;                                                       \
            bio_for_each_segment(_bvec, (bio), _iter)                                     \
            {                                                                             \
                DCORR_DEBUG("    segment: page=%p offset=%u len=%u\n",                    \
                            _bvec.bv_page,                                                \
                            _bvec.bv_offset,                                              \
                            _bvec.bv_len);                                                \
            }                                                                             \
        }                                                                                 \
        DCORR_DEBUG("----------------------------- BIO -----------------------------\n"); \
    } while (0)

#else
#define DCORR_DEBUG(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define DCORR_DEBUG_BIO(bio) ((void)(bio))
#endif

#endif
