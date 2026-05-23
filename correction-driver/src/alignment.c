#include "alignment.h"

/// @brief Рассчитывает выровненный номер сектора для невыровненного сектора
/// @param sector номер невыровненного сектора
/// @return номер выровненного сектора
sector_t align_data_sector(sector_t sector)
{
    return (sector / DATA_SIZE_SECTORS) * (CHUNK_SIZE_SECTORS) + (sector % DATA_SIZE_SECTORS);
}

/// @brief Рассчитывает количество секторов до следующего чанка для невыровненных секторов
/// @param sector номер невыровненного сектора
/// @return количество секторов до следующего чанка
sector_t misalign_data_sector(sector_t sector)
{
    return DATA_SIZE_SECTORS - (sector % DATA_SIZE_SECTORS);
}

/// @brief Рассчитывает номер начала данных в чанке для выровненного сектора
/// @param sector номер выровненного сектора
/// @return номер начала данных в чанке
sector_t start_data_sector(sector_t sector)
{
    return sector - (sector % CHUNK_SIZE_SECTORS);
}