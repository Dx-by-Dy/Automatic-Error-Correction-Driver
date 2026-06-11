#ifndef ALIGNMENT_H
#define ALIGNMENT_H

#include <linux/types.h>

#define DATA_SIZE_SECTORS 8
#define METADATA_SIZE_SECTORS 1
#define CHUNK_SIZE_SECTORS (DATA_SIZE_SECTORS + METADATA_SIZE_SECTORS)

/// @brief Преобразует логический сектор устройства в физический сектор
/// @details
/// После каждых DATA_SIZE_SECTORS секторов данных
/// на устройстве размещается METADATA_SIZE_SECTORS секторов метаданных.
/// Функция вычисляет физический сектор данных,
/// соответствующий логическому сектору.
/// @param sector Логический сектор
/// @return Физический сектор
static inline sector_t align_data_sector(sector_t sector)
{
    return (sector / DATA_SIZE_SECTORS) * (CHUNK_SIZE_SECTORS) + (sector % DATA_SIZE_SECTORS);
}

/// @brief Вычисляет количество секторов до конца текущего чанка данных (без метаданных)
/// @details
/// Используется при разбиении bio на части таким образом,
/// чтобы каждая часть не пересекала границу чанка.
/// @param sector Логический сектор
/// @return Количество секторов до конца текущего чанка данных
static inline sector_t sectors_until_datachunk_end(sector_t sector)
{
    return DATA_SIZE_SECTORS - (sector % DATA_SIZE_SECTORS);
}

/// @brief Вычисляет начало области данных чанка
/// @details
/// Для указанного логического сектора определяет физический сектор,
/// с которого начинается область данных соответствующего чанка.
/// @param sector Логический сектор
/// @return Физический сектор начала области данных чанка
static inline sector_t start_data_sector(sector_t sector)
{
    sector_t align_sector = align_data_sector(sector);
    return align_sector - (align_sector % CHUNK_SIZE_SECTORS);
}

/// @brief Вычисляет начало области метаданных чанка
/// @details
/// Для указанного логического сектора определяет физический сектор,
/// в котором располагаются метаданные соответствующего чанка.
/// @param sector Логический сектор
/// @return Физический сектор начала области метаданных чанка
static inline sector_t start_metadata_sector(sector_t sector)
{
    return start_data_sector(sector) + DATA_SIZE_SECTORS;
}

/// @brief Рассчитывает доступную емкость устройства
/// @details
/// Исключает из расчета сектора метаданных,
/// размещаемые после каждого чанка данных.
/// @param sector Полная емкость нижележащего устройства
/// @return Доступная логическая емкость устройства
static inline sector_t device_new_capacity(sector_t sector)
{
    return sector / CHUNK_SIZE_SECTORS * DATA_SIZE_SECTORS;
}

#endif