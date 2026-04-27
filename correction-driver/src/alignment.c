#include "alignment.h"

/// @brief Рассчитывает выровненный номер сектора для невыровненного сектора
/// @param sector номер невыровненного сектора
/// @return номер выровненного сектора
sector_t align_data_sector(sector_t sector)
{
    return ((sector / (DATA_SIZE_SECTORS - 1)) * (CHUNK_SIZE_SECTORS - 1)) + (sector % (DATA_SIZE_SECTORS - 1));
}

/// @brief Рассчитывает количество секторов до следующей границы выравнивания для невыровненных секторов
/// @param sector номер невыровненного сектора
/// @return количество секторов до следующей границы выравнивания
sector_t misalign_data_sector(sector_t sector)
{
    return DATA_SIZE_SECTORS - (sector % DATA_SIZE_SECTORS);
}