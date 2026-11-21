# Диаграммы

Ситуации из [ARCHITECTURE.md](ARCHITECTURE.md) в картинках, каждая с тестами, которые её покрывают. Термины — в
[глоссарии](ARCHITECTURE.md#глоссарий); тесты описаны в [TESTS.md](TESTS.md) и лежат в [`tests/`](../../tests).
`tools/check-docs.py` проверяет, что каждая диаграмма здесь разбирается. То, что драйвер сегодня делает неверно, каждый
случай — строгий `xfail`, нарисовано в конце, в разделе [Случаи, которые сейчас не
проходят](#случаи-которые-сейчас-не-проходят).

## Стек

```mermaid
flowchart TB
    fs["Файловая система или приложение"]
    subgraph driver["dm-dcorr"]
        map["dcorr_map: ждёт, если должен, но никогда собственного нижнего bio"]
        cache["Кэш: 64 MiB грязных чанков"]
        worker["Воркер: обратная запись, flush, discard"]
        meta["Метаданные в RAM: 32 области, обе копии"]
        bitmap["Битовая карта записанных чанков, целиком в RAM"]
        parts["transform_wq: чтения и задания, работа с CRC"]
    end
    lower["Нижнее устройство, отформатированное dcorrsetup"]
    fs -- "bio, разрезанные device mapper по чанкам в 4 KiB" --> map
    map -- "записи, завершаются сразу" --> cache
    map -- "чтения чанков не из кэша" --> parts
    map -- "flush, FUA, discard" --> worker
    worker --> cache
    worker -- "задания" --> parts
    parts --> meta
    worker --> bitmap
    map -. "чанк никогда не записан: нули" .-> bitmap
    parts -- "данные и ведущие метаданные" --> lower
    worker -- "flush, замыкающие метаданные, битовая карта" --> lower
```

Покрыто всем набором; от начала до конца — [`test_data.py`](../../tests/test_data.py) (`test_roundtrip`,
`test_random_writes_match_a_reference_copy`), [`test_filesystem.py`](../../tests/test_filesystem.py) и
[`test_fio.py`](../../tests/test_fio.py).

## Формат

```mermaid
flowchart TB
    subgraph device["Нижнее устройство: группы одного размера, по умолчанию 1 GiB"]
        direction LR
        g0["группа 0"] --- g1["группа 1"] --- gdots["..."] --- glast["группа G-1, может быть короткой"]
    end
    subgraph group["Группа в 1 GiB"]
        direction LR
        header["заголовок, 1 MiB: суперблок, ведущая битовая карта этой группы, замыкающая битовая карта предыдущей, грязные полосы"] --- r0["регион 0"] --- rdots["..."] --- r247["регион 247"]
    end
    subgraph region["Регион i, 4,125 MiB"]
        direction LR
        trail["замыкающая копия региона i-1, 128 секторов"] --- lead["ведущая копия региона i, 128 секторов"] --- slots["1024 слота по 8 секторов"]
    end
    subgraph columns["Слоты группы в 32 колонках"]
        direction LR
        data["колонки с 0 по 29: данные, в логическом порядке"] --- parity["колонки 30 и 31: чётность P и Q, зарезервированы"]
    end
    device --> group --> region
    group --> columns
```

Покрыто [`test_data.py`](../../tests/test_data.py): `test_capacity_excludes_metadata_and_parity`,
`test_layout_of_the_chunks_at_the_borders`, `test_data_lands_at_the_layout_position`,
`test_metadata_is_written_outside_the_data`; [`test_superblock.py`](../../tests/test_superblock.py):
`test_dcorrsetup_gives_the_layout_of_the_tests`, `test_every_region_lies_where_the_layout_says`,
`test_data_never_lands_in_the_parity_columns_nor_outside_the_regions`,
`test_the_header_of_every_group_holds_its_superblock_and_bitmaps`.

## Выбор суперблока

```mermaid
flowchart TD
    start(["Конструктор"]) --> read0["Прочитать суперблок группы 0"]
    read0 --> valid0{"Годен?"}
    valid0 -- да --> read1["Прочитать группу 1 по размеру группы, записанному в нём"]
    valid0 -- нет --> probe["Перебрать начало группы 1 для каждого размера, от 16 MiB до 4 GiB: побеждает первая годная копия"]
    read1 --> pick{"Годные копии"}
    probe --> pick
    pick -- "ни одной" --> refuse(["Отказать таблице"])
    pick -- "одна или две" --> take["Взять годную с большим поколением, предупредить о другой"]
    take --> checks{"Размер нижнего устройства и длина таблицы как при форматировании?"}
    checks -- нет --> refuse
    checks -- да --> resume(["Первый resume: прочитать заголовок каждой группы, проверить суперблоки со 2-го, загрузить битовую карту"])
```

Покрыто [`test_superblock.py`](../../tests/test_superblock.py): `test_a_device_without_a_superblock_is_refused`,
`test_one_damaged_copy_is_covered_by_the_other`, `test_both_damaged_copies_are_refused`,
`test_group_1_is_found_for_each_size_when_group_0_is_damaged`, `test_the_copy_with_the_larger_generation_is_taken`,
`test_a_device_of_another_size_is_refused`, `test_a_wrong_field_in_both_copies_is_refused`;
[`test_target.py`](../../tests/test_target.py): `test_a_length_other_than_the_capacity_is_rejected`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_the_superblock_of_every_other_group_is_checked`.
Поиск берёт и копию, сохранённую как данные: [Поиск берёт копию, сохранённую как
данные](#поиск-берёт-копию-сохранённую-как-данные).

## Путь записи

```mermaid
sequenceDiagram
    participant Up as Верхний уровень
    participant Map as dcorr_map
    participant Cache as Кэш
    participant W as Воркер
    participant Meta as Область метаданных в RAM
    participant Low as Нижнее устройство
    Up->>Map: запись чанка или его части
    Map->>Cache: копия в элемент чанка
    Map-->>Up: сразу завершить
    Note over W: позже - по возрасту, под давлением или для flush, записи FUA, suspend
    W->>Cache: выбрать элемент, теперь он под обратной записью
    W->>W: ждать чтений чанка в полёте
    W->>W: барьер и согласование, если нужно, см. ниже
    W->>Meta: положить новые CRC в ведущую копию
    W->>Low: ведущий сектор метаданных с FUA
    Low-->>W: долговечен
    W->>Low: данные
    Low-->>W: готово
    W->>Cache: освободить элемент, при первой обратной записи установить бит в RAM
    Note over W,Low: замыкающая копия и бит следуют со следующей синхронизацией
```

Покрыто [`test_cache.py`](../../tests/test_cache.py): `test_a_write_reaches_the_lower_device_on_a_flush`,
`test_dirty_data_is_written_back_by_age`, `test_a_partial_chunk_writes_only_its_sectors`,
`test_writes_larger_than_the_cache_wait_for_free_entries`, `test_a_write_back_waits_for_a_read_in_flight`;
[`test_crash.py`](../../tests/test_crash.py): `test_the_leading_copy_is_durable_before_the_data`;
[`test_metadata.py`](../../tests/test_metadata.py): `test_a_write_back_reads_nothing_when_the_metadata_is_in_ram`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_first_write_reads_back_with_zeros_around_it`.

## Путь чтения

```mermaid
flowchart TD
    read(["Чтение чанка или его части"]) --> cached{"Секторы грязные в кэше?"}
    cached -- да --> copy["Скопировать их из элемента"]
    cached -- нет --> bit{"Бит чанка установлен?"}
    bit -- нет --> zeros["Нули, без чтения нижнего устройства"]
    bit -- да --> register["Встать в дерево чтений, скопировать обе записи из RAM"]
    register --> lower["Прочитать данные с нижнего устройства"]
    lower --> error{"Ошибка снизу?"}
    error -- да --> eio["BLK_STS_IOERR только для этого bio"]
    error -- нет --> crc{"Каждый сектор совпадает с ведущим или замыкающим CRC?"}
    crc -- да --> ok(["Завершить"])
    crc -- нет --> eio
    copy --> ok
    zeros --> ok
```

Покрыто [`test_cache.py`](../../tests/test_cache.py): `test_a_read_of_a_partly_dirty_chunk`,
`test_a_dirty_sector_reads_while_a_clean_one_is_damaged`, `test_a_read_of_a_clean_sector_waits_for_the_write_back`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_device_of_random_data_reads_zeros_once_formatted`;
[`test_corruption.py`](../../tests/test_corruption.py): `test_data_corruption_fails_only_that_sector`,
`test_crc_corruption_in_one_copy_is_covered_by_the_other`;
[`test_metadata.py`](../../tests/test_metadata.py): `test_a_read_takes_one_lower_read_when_the_metadata_is_in_ram`;
[`test_lower_errors.py`](../../tests/test_lower_errors.py): `test_failed_data_sector_fails_only_its_reads`.

## Элемент кэша

```mermaid
stateDiagram-v2
    [*] --> FREE
    FREE --> DIRTY: запись сверху
    DIRTY --> DIRTY: ещё одна запись
    DIRTY --> WRITING: выбран воркером
    WRITING --> FREE: все задания удались
    WRITING --> FAILED: задание не удалось
    FAILED --> DIRTY: flush, suspend или запись в него
    DIRTY --> FREE: discard чанка
    FAILED --> FREE: discard чанка
    note right of WRITING
        записи в него и чтения его
        чистых секторов ждут в dcorr_map
    end note
    note right of FAILED
        каждый flush отказывает, пока такой есть
        когда неудачны все элементы, записи отказывают
    end note
```

Покрыто [`test_cache.py`](../../tests/test_cache.py): `test_a_suspend_writes_back`,
`test_a_read_of_a_clean_sector_waits_for_the_write_back`;
[`test_lower_errors.py`](../../tests/test_lower_errors.py): `test_failed_write_is_reported`,
`test_writes_fail_while_reads_go_on`, `test_a_cache_full_of_failed_chunks_refuses_writes`;
[`test_discard.py`](../../tests/test_discard.py): `test_data_in_the_cache_is_dropped_by_a_discard`.

## Синхронизация

```mermaid
sequenceDiagram
    participant Up as Flush сверху
    participant W as Воркер
    participant Bm as Битовая карта
    participant Low as Нижнее устройство
    Up->>W: пустой flush или запись FUA
    W->>Low: записать обратно всё грязное, ждать
    W->>Low: flush
    Note over Low: записанные обратно данные долговечны
    W->>Bm: следующее поколение каждого изменённого блока
    W->>Low: первая копия каждого изменённого блока
    W->>Low: flush
    Note over Low: бит на устройстве означает долговечные данные
    W-->>Up: завершить, с ошибкой, если не удался элемент или блок
    W->>Low: замыкающие метаданные записанных обратно чанков
    W->>Low: вторая копия каждого изменённого блока
    W->>Low: flush
    Note over Low: обе копии долговечны до следующей обратной записи
```

Покрыто [`test_durability.py`](../../tests/test_durability.py) (целиком);
[`test_metadata.py`](../../tests/test_metadata.py): `test_the_trailing_copy_is_written_after_a_flush`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_bit_reaches_the_device_only_with_a_flush`,
`test_a_flush_fails_when_the_first_copy_of_a_block_fails_to_write`, `test_a_second_copy_that_fails_to_write_is_counted`;
[`test_crash.py`](../../tests/test_crash.py): `test_flushed_writes_survive_a_crash`.

Та же синхронизация выполняется для барьера, когда занята половина областей метаданных, и при suspend. Если первый
flush не удался, flush сверху отказывают и замыкающая копия не пишется; чанки, записанные обратно, остаются
закреплёнными до следующей синхронизации: [Неудавшийся flush нижнего устройства](#неудавшийся-flush-нижнего-устройства).

## Неудавшийся flush нижнего устройства

```mermaid
sequenceDiagram
    participant W as Воркер
    participant M as Метаданные в RAM
    participant Low as Нижнее устройство
    W->>Low: обратная запись чанка A, версия 2: ведущая копия с FUA, затем данные
    W->>M: A записан после flush, его область закреплена
    W->>Low: flush
    Low-->>W: отказ
    Note over M: область остаётся закреплённой, A всё ещё считается записанным после flush
    W->>W: следующая обратная запись A, версия 3: сначала барьер
    W->>Low: flush
    alt flush снова отказывает
        Low-->>W: отказ
        W->>W: обратная запись отменяется, A хранит версию 3 в RAM, flush отказывают
    else flush удаётся
        Low-->>W: готово, версия 2 долговечна
        W->>Low: замыкающая копия A получает версию 2, затем ведущая версию 3 и данные
    end
```

Покрыто [`test_lower_errors.py`](../../tests/test_lower_errors.py):
`test_a_chunk_written_back_again_after_a_failed_flush_takes_a_barrier`, барьер с неудавшимся flush между двумя
обратными записями, как и без него, и `test_a_chunk_whose_barrier_fails_is_not_written_back`.

## Крах между двумя копиями

Что хранит сектор после краха в каждой точке обратной записи новых данных поверх старых и что читается.

```mermaid
stateDiagram-v2
    direction LR
    steady: данные старые, ведущая старая, замыкающая старая
    leadnew: данные старые, ведущая НОВАЯ, замыкающая старая
    datanew: данные НОВЫЕ, ведущая НОВАЯ, замыкающая старая
    settled: данные НОВЫЕ, ведущая НОВАЯ, замыкающая НОВАЯ
    [*] --> steady
    steady --> leadnew: ведущий сектор с FUA
    leadnew --> datanew: данные записаны, flush
    datanew --> settled: замыкающая копия после flush
    note right of leadnew: старые данные совпадают с замыкающей копией, читаются старые
    note right of datanew: новые данные совпадают с ведущей копией, читаются новые
```

Крах в любом состоянии оставляет каждый сектор читаемым, старым или новым. Не покрыто: крах в средних состояниях
вместе с потерянным сектором той копии, которая совпадает, что последующая запись соседа делает постоянным, см.
[Сектор метаданных, восстановленный из одной копии](#сектор-метаданных-восстановленный-из-одной-копии). Крах после
flush сверху и до замыкающей копии оставляет состояние с новыми данными, и ничто не продвигает его дальше до
следующей обратной записи: [Замыкающая копия после перезапуска](#замыкающая-копия-после-перезапуска).

Покрыто [`test_crash.py`](../../tests/test_crash.py): `test_a_write_cut_between_data_and_metadata_reads_old_or_new`,
`test_chunks_of_a_region_cut_between_flushes_read_old_or_new_each`, `test_ext4_survives_a_crash_after_each_fsync`,
`test_ext4_survives_a_crash_at_any_flush`.

## Перед обратной записью: барьер и согласование

```mermaid
flowchart TD
    start(["Элемент выбран для обратной записи"]) --> since{"Чанк записывался обратно после последнего flush?"}
    since -- да --> barrier["Барьер: ждать заданий, синхронизировать"]
    since -- нет --> clear{"Бит очищен, пока очистка discard ещё не синхронизирована?"}
    clear -- да --> barrier
    clear -- нет --> unwritten
    barrier --> unwritten{"Бит чанка очищен?"}
    unwritten -- "да, и очистки синхронизированы" --> whole["Первая обратная запись: весь чанк, нули вокруг данных, без согласования"]
    unwritten -- нет --> differ{"Копии различаются в секторах для записи?"}
    unwritten -- "да, но синхронизация не удалась: согласуется как записанный" --> differ
    differ -- нет --> jobs(["Отправить задания"])
    differ -- да --> settle["Согласование: прочитать чанк"]
    settle --> match{"Каждый такой сектор совпадает"}
    match -- "с ведущей копией" --> fua["Записать этот CRC в замыкающую копию с FUA"]
    match -- "с замыкающей копией" --> jobs
    match -- "ни с одной" --> count["Учесть несовпадение, оставить его видимым"]
    fua --> jobs
    count --> jobs
    whole --> jobs
```

Покрыто [`test_crash.py`](../../tests/test_crash.py):
`test_a_chunk_written_back_twice_between_flushes_reads_one_of_its_versions`,
`test_a_second_crash_after_one_between_the_copies`, `test_first_writes_cut_anywhere_read_zeros_or_new`,
`test_a_write_after_a_discard_cut_anywhere_reads_zeros_or_new`;
[`test_corruption.py`](../../tests/test_corruption.py): `test_a_sector_whose_copies_differ_is_read_before_it_is_written`,
`test_only_the_sectors_written_are_read_first`, `test_a_sector_matching_neither_copy_is_counted_before_it_is_written`;
[`test_discard.py`](../../tests/test_discard.py): `test_a_write_after_a_discard_is_written_whole_after_a_barrier`,
`test_a_second_write_after_a_flushed_discard_needs_no_barrier`.

## Битовая карта: выбор копии блока

```mermaid
flowchart TD
    start(["Первый resume: прочитаны обе копии блока"]) --> lv{"Ведущая копия годна? CRC от соли, группа, индекс, роль"}
    lv -- да --> both{"Замыкающая тоже годна?"}
    lv -- нет --> tv{"Замыкающая годна?"}
    both -- да --> newer["Взять ту, у которой больше поколение; более старая остаётся на устройстве"]
    both -- нет --> single["Взять ведущую, починить другую следующим flush"]
    tv -- да --> single2["Взять замыкающую, починить другую следующим flush"]
    tv -- нет --> ro["Диапазон только для чтения: чанки читаются как записанные, решает CRC, записи и discard отказывают"]
```

Покрыто [`test_bitmap.py`](../../tests/test_bitmap.py): `test_one_damaged_copy_is_covered_and_repaired`,
`test_the_copy_with_the_larger_generation_is_taken`, `test_a_block_of_another_place_or_device_is_not_taken`,
`test_a_block_invalid_in_both_copies_makes_its_range_read_only`, `test_a_discard_touching_a_read_only_block_fails_whole`,
`test_a_reload_keeps_the_bits_the_old_table_sets`; [`test_lost_writes.py`](../../tests/test_lost_writes.py):
`test_a_lost_copy_of_a_block_of_the_bitmap_is_covered_by_the_other`. Чего более старая копия стоит позже: [Более
старая копия блока битовой карты](#более-старая-копия-блока-битовой-карты); что диапазон только для чтения даёт
для чанка, обнулённого раньше: [Обнулённый чанк в диапазоне только для
чтения](#обнулённый-чанк-в-диапазоне-только-для-чтения).

## Discard и его ловушка

```mermaid
sequenceDiagram
    participant Up as Верхний уровень
    participant Map as dcorr_map
    participant W as Воркер
    participant Low as Нижнее устройство
    Up->>Map: discard
    alt ни одного целого чанка
        Map-->>Up: сразу завершить
    else затрагивает диапазон только для чтения
        Map-->>Up: ошибка
    else
        Map->>W: поставить в очередь
        W->>W: ждать обратных записей в полёте
        W->>W: сбросить элементы его целых чанков, очистить их биты, учесть очистку
        W-->>Up: завершить - внизу ничего не записано
    end
    Note over Low: на устройстве бит всё ещё установлен до следующей синхронизации
    Up->>Map: запись в чанк после discard
    W->>W: первая обратная запись, пока очистка не синхронизирована
    W->>Low: барьер - синхронизация, очищенный бит попадает на устройство
    W->>Low: весь чанк, ведущая копия с FUA, затем данные
    Note over Low: крах теперь читает нули, но никогда не чанк, не совпадающий ни с одной копией
```

Покрыто [`test_discard.py`](../../tests/test_discard.py) (целиком); [`test_crash.py`](../../tests/test_crash.py):
`test_a_discard_cut_anywhere_reads_old_or_zeros`, `test_a_write_after_a_discard_cut_anywhere_reads_zeros_or_new`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_discard_touching_a_read_only_block_fails_whole`.

## Write zeroes

```mermaid
flowchart TD
    wz(["Write zeroes с сектора 3 чанка 4 по сектор 5 чанка 7"]) --> offered{"Есть ли у нижнего устройства write zeroes?"}
    offered -- нет --> writes["не предлагается: ядро пишет нулевые страницы, обычными записями через кэш"]
    offered -- да --> ro{"Затрагивает диапазон только для чтения?"}
    ro -- да --> fail["отклонено"]
    ro -- нет --> ends["неполные чанки 4 и 7: нули пишутся в их элементы, как запись"]
    ends --> whole["целые чанки 5 и 6: к воркеру как discard, элементы сброшены, биты очищены"]
    whole --> done["завершено; нули читаются из кэша и без чтения снизу"]
    done --> durable["долговечно после следующего flush, как запись"]
```

Покрыто [`test_discard.py`](../../tests/test_discard.py): `test_the_device_offers_discard_in_chunks_and_write_zeroes`,
`test_write_zeroes_reads_zeros_and_keeps_the_neighbours`, `test_write_zeroes_survives_recreating_the_device`,
`test_write_zeroes_over_data_in_the_cache`, `test_blkdiscard_z_zeroes_through_write_zeroes`,
`test_write_zeroes_inside_one_chunk_zeroes_only_its_sectors`; [`test_lower_errors.py`](../../tests/test_lower_errors.py):
`test_write_zeroes_is_not_offered_over_a_lower_device_without_it`.

## Сбои нижнего устройства

```mermaid
flowchart LR
    subgraph reads["Чтение не удаётся"]
        rd["сектор данных"] --> rdo["отказывают только bio над ним"]
        rm1["сектор метаданных, одна копия"] --> rm1o["берётся из другой копии, с предупреждением"]
        rm2["сектор метаданных, обе копии"] --> rm2o["отказывают его 8 чанков, чтения и записи"]
    end
    subgraph writes["Запись не удаётся"]
        wd["обратная запись"] --> wdo["элемент FAILED, данные сохранены, flush отказывают, повтор"]
        wf["каждая обратная запись"] --> wfo["кэш заполняется неудачными элементами, новые записи отклоняются, чтения продолжаются"]
        wt["замыкающие метаданные"] --> wto["учитывается, ведущая копия продолжает работу"]
        wb["первая копия блока битовой карты"] --> wbo["flush отказывает, блок остаётся грязным"]
    end
```

Покрыто [`test_lower_errors.py`](../../tests/test_lower_errors.py) (целиком);
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_flush_fails_when_the_first_copy_of_a_block_fails_to_write`,
`test_a_second_copy_that_fails_to_write_is_counted`. Сектор метаданных, не читающийся в одной копии после краха:
[Сектор метаданных, восстановленный из одной копии](#сектор-метаданных-восстановленный-из-одной-копии);
неудавшийся flush: [Неудавшийся flush нижнего устройства](#неудавшийся-flush-нижнего-устройства).

## Каждая ошибка — сигнал

```mermaid
flowchart LR
    err(["Ошибка: неудачное чтение, обратная запись или flush, несовпадение CRC, метаданные или битовая карта"]) --> cnt["растёт её счётчик в dmsetup status"]
    err --> log["строка в журнале ядра: имя из dmsetup, логический сектор; с ограничением частоты, одним на все устройства"]
    err --> first{"Первая с момента создания таблицы?"}
    first -- да --> ev["рабочий элемент поднимает событие device mapper"]
    ev --> wait["dmsetup wait, dmeventd: пользователь читает счётчики и переносит данные"]
    first -- нет --> none["события нет"]
```

Покрыто [`test_lower_errors.py`](../../tests/test_lower_errors.py):
`test_the_first_error_raises_one_device_mapper_event`, `test_a_failed_read_is_counted_and_logged_with_the_device`,
`test_a_failed_metadata_read_is_counted_in_sectors`, `test_a_failed_flush_is_counted`,
`test_failed_write_is_reported`; [`test_corruption.py`](../../tests/test_corruption.py):
`test_every_damaged_sector_of_a_read_is_counted_and_logged`,
`test_a_flood_of_mismatches_is_counted_whole_and_logged_rate_limited`. Ограничение каждого места кода общее для
всех устройств, так что поток на одном скрывает первые ошибки другого на 5 с: строгий `xfail`
`test_a_flood_on_one_device_does_not_hide_the_errors_of_another`.

## Потерянные записи

Запись, подтверждённая нижним устройством, но так и не попавшая на его носитель.

```mermaid
flowchart TD
    lost(["Обратная запись, частично потерянная"]) --> what{"Что потеряно?"}
    what -- "данные перезаписи" --> a1["До flush: читаются старые данные, с ними совпадает замыкающая копия"]
    a1 --> a2["После flush: обе копии хранят новый CRC, чанк отказывает"]
    what -- "данные первой записи" --> b1["Отказывает сразу: нули внизу не совпадают ни с одной копией, благодаря затравке"]
    what -- "ведущий сектор метаданных" --> c1["Его покрывает замыкающая копия, следующая обратная запись согласует"]
    what -- "замыкающий сектор метаданных, или крах до него" --> t1["Старый CRC остаётся до следующей обратной записи: возвращённые старые данные проходят, навсегда"]
    what -- "одна копия блока битовой карты" --> d1["Берётся другая копия, более нового поколения"]
    what -- "данные и обе копии метаданных" --> e1["Старые данные проходят навсегда: слепое пятно, для чётности этапа коррекции"]
```

Покрыто [`test_lost_writes.py`](../../tests/test_lost_writes.py) (целиком); затравка —
[`test_corruption.py`](../../tests/test_corruption.py): `test_zeroed_chunk_is_detected`,
`test_chunk_copied_elsewhere_is_detected`, `test_sectors_swapped_inside_a_chunk_with_their_crcs_are_detected`,
`test_a_zeroed_region_with_its_chunks_written_is_detected`, `test_a_region_shifted_whole_with_its_metadata_is_detected`,
`test_a_chunk_from_another_device_is_detected`. Потерянный замыкающий сектор нарисован в разделе [Замыкающая копия
после перезапуска](#замыкающая-копия-после-перезапуска).

## Случаи, которые сейчас не проходят

Найдены при просмотре `src/` 2026-11-17, каждый закреплён строгим `xfail` с пунктом в [TODO.md](TODO.md);
диаграмма показывает путь к неверному результату. Позитивный контроль каждого теста проходит.

### Более старая копия блока битовой карты

```mermaid
sequenceDiagram
    participant Drv as Драйвер
    participant L as Ведущая копия
    participant T as Замыкающая копия
    Note over L,T: поколение 2 в обеих, с битом чанка A
    Drv->>L: первая запись чанка B, flush: поколение 3 с A и B
    Note over Drv,T: крах до второй копии, или её запись не удалась
    Drv->>Drv: создан снова: обе годны, берётся более новая
    Note over T: поколение 2 без B, не помечено к ремонту, поэтому остаётся
    Note over L: позже ведущая копия теряется
    Drv->>T: создан снова: годна только замыкающая копия
    Drv->>Drv: чанк B читается как нули, без ошибки
    Drv->>L: ремонт при следующем flush пишет поколение 2 в обе
```

Закреплено `test_an_older_copy_is_rewritten_before_the_newer_is_lost`: с одним flush между ними — строгий `xfail`;
с первой записью в другой чанк блока между ними, которая переписывает обе копии, тест проходит.

### Обнулённый чанк в диапазоне только для чтения

```mermaid
flowchart TD
    w["Чанк записан и сброшен flush: данные OLD, обе копии его CRC — от OLD, бит стоит"] --> z["Discard или write zeroes: бит очищен, внизу ничего не записано"]
    z --> r1["Читается как нули"]
    r1 --> lost["Обе копии его блока битовой карты становятся негодными"]
    lost --> ro["Диапазон только для чтения: каждый чанк читается как записанный, решает CRC"]
    ro --> wrong["OLD внизу совпадает со своими старыми CRC: OLD возвращается без ошибки, хотя верны нули или ошибка"]
```

Закреплено `test_a_zeroed_chunk_in_a_read_only_block_never_reads_its_old_data`, для discard и write zeroes.

### Сектор метаданных, восстановленный из одной копии

```mermaid
flowchart TD
    crash["После краха во время обратной записи: у чанка Y данные NEW, ведущая NEW, замыкающая OLD"] --> fail["Ведущий сектор Y не читается"]
    fail --> fill["Загрузка: ведущая копия в RAM заполнена из замыкающей, у Y в обеих OLD"]
    fill --> eio1["Y отказывает: крах вместе с потерянным сектором совпадающей копии, по решению"]
    fill --> neigh["Записан обратно чанк X того же сектора метаданных"]
    neigh --> wr["Весь ведущий сектор записан из RAM: у Y и на устройстве OLD"]
    wr --> heal["Сектор снова читается"]
    heal --> eio2["Y по-прежнему отказывает, навсегда: данные NEW, обе копии OLD"]
```

Зеркальный случай: крах до данных оставляет данные OLD, ведущую NEW, замыкающую OLD; замыкающий сектор не
читается, заполняется NEW, и следующая синхронизация пишет NEW поверх него. Закреплено
`test_a_sector_rebuilt_from_one_copy_keeps_its_neighbours_readable`, оба случая — строгий `xfail`; с равными
копиями, позитивный контроль, Y читается.

### Замыкающая копия после перезапуска

```mermaid
stateDiagram-v2
    direction LR
    apart: данные NEW, ведущая NEW, замыкающая OLD
    read: создан снова, NEW читается, flush ничего не меняют
    back: диск возвращает OLD
    passes: OLD совпадает с замыкающей копией, читается без ошибки
    [*] --> apart: крах после flush сверху, до замыкающей копии, или потерянная запись замыкающей
    apart --> read
    read --> back: запись, потерянная из кэша диска
    back --> passes
    note right of read: ничто не согласует чанк до его следующей обратной записи
```

Закреплено `test_old_data_put_back_fails_once_the_new_was_read`: с потерянной замыкающей копией — строгий
`xfail`; с обеими записанными копиями возвращённые старые данные не проходят CRC.

### Поиск берёт копию, сохранённую как данные

```mermaid
flowchart TD
    fmt["Форматировано с группами по 32 MiB: группа 1 начинается с 32 MiB"] --> img["Образ суперблока группы 1 для групп по 16 MiB сохранён как данные, на 16 MiB, внутри группы 0"]
    img --> dmg["Группа 0 повреждена"]
    dmg --> p16["Поиск сначала пробует 16 MiB: образ годен для этого места"]
    p16 --> wrong["Взята разметка 16 MiB"]
    wrong --> refused["Длина таблицы не равна её ёмкости: отказ"]
    p16 -. "не читается" .-> truecopy["Настоящая копия на 32 MiB"]
```

Закреплено `test_a_superblock_stored_as_data_does_not_win_the_probe`. С таблицей под разметку образа устройство
поднялось бы на неверной разметке.

### Два устройства на одном нижнем

```mermaid
flowchart LR
    a["Устройство A: свои кэш, метаданные и битовая карта в RAM"] -- "первая запись чанка C, flush: бит поставлен" --> low[("Одно нижнее устройство")]
    b["Устройство B: битовая карта прочитана при его resume, раньше"] -- "чтение C" --> zeros["в RAM нет бита C: нули, без чтения вниз и без ошибки"]
    a -. "каждое пишет свою битовую карту поверх чужой" .- b
```

Закреплено `test_a_second_device_on_the_same_lower_device_is_refused_or_agrees`: device mapper принимает вторую
таблицу, так что второе устройство читает нули там, где первое записало.
