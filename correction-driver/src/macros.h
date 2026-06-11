#define DM_MSG_PREFIX "correction-driver"

#define DM_ERR(fmt, ...) \
    pr_err(DM_MSG_PREFIX ": " fmt, ##__VA_ARGS__)

#define DM_WARN(fmt, ...) \
    pr_warn(DM_MSG_PREFIX ": " fmt, ##__VA_ARGS__)

#define DM_DEBUG(fmt, ...) \
    pr_debug(DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)
