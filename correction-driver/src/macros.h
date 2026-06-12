#define DM_MSG_PREFIX "correction-driver"

#define DM_ERR(fmt, ...) \
    pr_err("[ERROR] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

#define DM_WARN(fmt, ...) \
    pr_warn("[WARN] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)

#define DM_DEBUG(fmt, ...) \
    pr_debug("[DEBUG] " DM_MSG_PREFIX " [%s]: " fmt, __func__, ##__VA_ARGS__)
