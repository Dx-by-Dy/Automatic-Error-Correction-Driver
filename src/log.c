#include "dm-dcorr.h"
#include "log.h"

/// @brief Prints a message of the device, named as dmsetup names it
/// @details
/// The name is looked up for each message, so a rename shows at once; if the
/// device has none, major:minor stands for it. Called through the DCORR_DEV_
/// macros of log.h, from process context with no spinlock held, as the lookup
/// takes a mutex of device mapper. That mutex guards only the name, so it
/// never waits for I/O.
void dcorr_log(struct dm_target *ti, enum dcorr_level level, const char *fmt, ...)
{
    char name[DM_NAME_LEN];
    struct va_format vaf;
    va_list args;

    if (dm_copy_name_and_uuid(dm_table_get_md(ti->table), name, NULL))
        strscpy(name, dm_table_device_name(ti->table));

    va_start(args, fmt);
    vaf.fmt = fmt;
    vaf.va = &args;
    switch (level)
    {
    case DCORR_LEVEL_ERR:
        pr_err("[ERROR] " DM_MSG_PREFIX " %s: %pV", name, &vaf);
        break;
    case DCORR_LEVEL_WARN:
        pr_warn("[WARN] " DM_MSG_PREFIX " %s: %pV", name, &vaf);
        break;
    case DCORR_LEVEL_INFO:
        pr_info("[INFO] " DM_MSG_PREFIX " %s: %pV", name, &vaf);
        break;
    }
    va_end(args);
}

/// @brief Raises the device mapper event of the first error
void dcorr_event_work(struct work_struct *work)
{
    struct dcorr_ctx *dc = container_of(work, struct dcorr_ctx, event_work);

    dm_table_event(dc->ti->table);
}

/// @brief Records that the device met an error: of the lower device, or damaged data or metadata
/// @details
/// The first one since the table was created raises a device mapper event,
/// which dmsetup wait and dmeventd see; the counters of dmsetup status tell
/// what it was. Later errors raise none, so that a failing device does not
/// keep the waiters busy. Any context: the event is raised from a work item,
/// as dm_table_event takes a mutex. Before the constructor returns there is
/// no context yet, and nothing to raise.
/// @param ti The target of the device
void dcorr_error(struct dm_target *ti)
{
    struct dcorr_ctx *dc = READ_ONCE(ti->private);

    if (dc && !test_and_set_bit(0, &dc->errors_seen))
        schedule_work(&dc->event_work);
}
