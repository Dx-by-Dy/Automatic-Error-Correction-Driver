#ifndef CORRECTION_DRIVER_H
#define CORRECTION_DRIVER_H

#include <linux/module.h>
#include <linux/device-mapper.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/bvec.h>
#include <linux/crc64.h>
#include <linux/workqueue.h>

#include "locker.h"
#include "bio_helper.h"
#include "trn_rq.h"
#include "trn_p_rq.h"

/// @brief Контекст DM-таргета
/// @details
/// Создаётся в dm_ctr и хранится в ti->private.
/// Содержит все ресурсы, необходимые для обработки запросов:
/// устройство нижнего уровня, очередь работ, bioset и таблицу блокировок.
struct dm_context
{
    /// @brief Устройство нижнего уровня
    struct dm_dev *dev;

    /// @brief Очередь работ для асинхронной обработки bio
    struct workqueue_struct *transform_wq;

    /// @brief Пул для выделения bio
    struct bio_set *transform_bs;

    /// @brief Таблица блокировок чанков
    struct locker *locker;
};

#endif