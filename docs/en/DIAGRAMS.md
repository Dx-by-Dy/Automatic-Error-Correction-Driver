# Diagrams

The situations of [ARCHITECTURE.md](ARCHITECTURE.md) as pictures, each with the tests that cover it. The terms are
in the [glossary](ARCHITECTURE.md#glossary); the tests are described in [TESTS.md](TESTS.md), and live in
[`tests/`](../../tests). `tools/check-docs.py` checks that every diagram here parses.

## The stack

```mermaid
flowchart TB
    fs["Filesystem or application"]
    subgraph driver["dm-dcorr"]
        map["dm_map: waits if it must, never for its own lower bio"]
        cache["Cache: 64 MiB of dirty chunks"]
        worker["Worker: write back, flushes, discards"]
        meta["Metadata in RAM: 32 areas, both copies"]
        bitmap["Bitmap of written chunks, whole in RAM"]
        parts["transform_wq: reads and jobs, CRC work"]
    end
    lower["Lower device, formatted by dcorrsetup"]
    fs -- "bios cut at 4 KiB chunks by device mapper" --> map
    map -- "writes, completed at once" --> cache
    map -- "reads of chunks not in the cache" --> parts
    map -- "flushes, FUA, discards" --> worker
    worker --> cache
    worker -- "jobs" --> parts
    parts --> meta
    worker --> bitmap
    map -. "chunk never written: zeros" .-> bitmap
    parts -- "data and leading metadata" --> lower
    worker -- "flushes, trailing metadata, bitmap" --> lower
```

Covered by the whole suite; end to end by [`test_data.py`](../../tests/test_data.py) (`test_roundtrip`,
`test_random_writes_match_a_reference_copy`), [`test_filesystem.py`](../../tests/test_filesystem.py) and
[`test_fio.py`](../../tests/test_fio.py).

## The layout

```mermaid
flowchart TB
    subgraph device["Lower device: groups of one size, 1 GiB by default"]
        direction LR
        g0["group 0"] --- g1["group 1"] --- gdots["..."] --- glast["group G-1, may be short"]
    end
    subgraph group["Group of 1 GiB"]
        direction LR
        header["header, 1 MiB: superblock, leading bitmap of this group, trailing bitmap of the group before, dirty stripes"] --- r0["region 0"] --- rdots["..."] --- r247["region 247"]
    end
    subgraph region["Region i, 4.125 MiB"]
        direction LR
        trail["trailing copy of region i-1, 128 sectors"] --- lead["leading copy of region i, 128 sectors"] --- slots["1024 slots of 8 sectors"]
    end
    subgraph columns["The slots of a group in 32 columns"]
        direction LR
        data["columns 0 to 29: data, in logical order"] --- parity["columns 30 and 31: P and Q parity, reserved"]
    end
    device --> group --> region
    group --> columns
```

Covered by [`test_data.py`](../../tests/test_data.py): `test_capacity_excludes_metadata_and_parity`,
`test_layout_of_the_chunks_at_the_borders`, `test_data_lands_at_the_layout_position`,
`test_metadata_is_written_outside_the_data`; [`test_superblock.py`](../../tests/test_superblock.py):
`test_dcorrsetup_gives_the_layout_of_the_tests`, `test_every_region_lies_where_the_layout_says`,
`test_data_never_lands_in_the_parity_columns_nor_outside_the_regions`,
`test_the_header_of_every_group_holds_its_superblock_and_bitmaps`.

## Choosing the superblock

```mermaid
flowchart TD
    start(["Constructor"]) --> read0["Read the superblock of group 0"]
    read0 --> valid0{"Valid?"}
    valid0 -- yes --> read1["Read group 1 at the size of a group it records"]
    valid0 -- no --> probe["Probe the start of group 1 for every size, from 16 MiB to 4 GiB"]
    read1 --> pick{"Valid copies"}
    probe --> pick
    pick -- "none" --> refuse(["Refuse the table"])
    pick -- "one or two" --> take["Take the valid one with the larger generation, warn about the other"]
    take --> checks{"Size of the lower device and table length as formatted?"}
    checks -- no --> refuse
    checks -- yes --> resume(["First resume: read the header of every group, check superblocks 2 and on, load the bitmap"])
```

Covered by [`test_superblock.py`](../../tests/test_superblock.py): `test_a_device_without_a_superblock_is_refused`,
`test_one_damaged_copy_is_covered_by_the_other`, `test_both_damaged_copies_are_refused`,
`test_group_1_is_found_for_each_size_when_group_0_is_damaged`, `test_the_copy_with_the_larger_generation_is_taken`,
`test_a_device_of_another_size_is_refused`, `test_a_wrong_field_in_both_copies_is_refused`;
[`test_target.py`](../../tests/test_target.py): `test_a_length_other_than_the_capacity_is_rejected`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_the_superblock_of_every_other_group_is_checked`.

## The write path

```mermaid
sequenceDiagram
    participant Up as Layer above
    participant Map as dm_map
    participant Cache as Cache
    participant W as Worker
    participant Meta as Metadata area in RAM
    participant Low as Lower device
    Up->>Map: write of a chunk or part of one
    Map->>Cache: copy into the entry of the chunk
    Map-->>Up: complete at once
    Note over W: later - by age, under pressure, or for a flush, a FUA write, a suspend
    W->>Cache: pick the entry, now under write back
    W->>W: wait for the reads in flight on the chunk
    W->>W: barrier and settle if needed, see below
    W->>Meta: put the new CRCs into the leading copy
    W->>Low: leading metadata sector with FUA
    Low-->>W: durable
    W->>Low: the data
    Low-->>W: done
    W->>Cache: free the entry, set the bit in RAM on a first write back
    Note over W,Low: the trailing copy and the bit follow with the next sync
```

Covered by [`test_cache.py`](../../tests/test_cache.py): `test_a_write_reaches_the_lower_device_on_a_flush`,
`test_dirty_data_is_written_back_by_age`, `test_a_partial_chunk_writes_only_its_sectors`,
`test_writes_larger_than_the_cache_wait_for_free_entries`, `test_a_write_back_waits_for_a_read_in_flight`;
[`test_crash.py`](../../tests/test_crash.py): `test_the_leading_copy_is_durable_before_the_data`;
[`test_metadata.py`](../../tests/test_metadata.py): `test_a_write_back_reads_nothing_when_the_metadata_is_in_ram`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_first_write_reads_back_with_zeros_around_it`.

## The read path

```mermaid
flowchart TD
    read(["Read of a chunk, or part of one"]) --> cached{"Sectors dirty in the cache?"}
    cached -- yes --> copy["Copy them from the entry"]
    cached -- no --> bit{"Bit of the chunk set?"}
    bit -- no --> zeros["Zeros, no read of the lower device"]
    bit -- yes --> register["Register in the tree of reads, copy both entries from RAM"]
    register --> lower["Read the data from the lower device"]
    lower --> error{"Lower error?"}
    error -- yes --> eio["BLK_STS_IOERR for this bio only"]
    error -- no --> crc{"Each sector matches the leading or the trailing CRC?"}
    crc -- yes --> ok(["Complete"])
    crc -- no --> eio
    copy --> ok
    zeros --> ok
```

Covered by [`test_cache.py`](../../tests/test_cache.py): `test_a_read_of_a_partly_dirty_chunk`,
`test_a_dirty_sector_reads_while_a_clean_one_is_damaged`, `test_a_read_of_a_clean_sector_waits_for_the_write_back`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_device_of_random_data_reads_zeros_once_formatted`;
[`test_corruption.py`](../../tests/test_corruption.py): `test_data_corruption_fails_only_that_sector`,
`test_crc_corruption_in_one_copy_is_covered_by_the_other`;
[`test_metadata.py`](../../tests/test_metadata.py): `test_a_read_takes_one_lower_read_when_the_metadata_is_in_ram`;
[`test_lower_errors.py`](../../tests/test_lower_errors.py): `test_failed_data_sector_fails_only_its_reads`.

## An entry of the cache

```mermaid
stateDiagram-v2
    [*] --> FREE
    FREE --> DIRTY: write from above
    DIRTY --> DIRTY: another write
    DIRTY --> WRITING: picked by the worker
    WRITING --> FREE: every job succeeded
    WRITING --> FAILED: a job failed
    FAILED --> DIRTY: flush, suspend, or a write to it
    DIRTY --> FREE: discard of the chunk
    FAILED --> FREE: discard of the chunk
    note right of WRITING
        writes to it and reads of its
        clean sectors wait in dm_map
    end note
    note right of FAILED
        every flush fails while one is left
        when all entries failed, writes fail
    end note
```

Covered by [`test_cache.py`](../../tests/test_cache.py): `test_a_suspend_writes_back`,
`test_a_read_of_a_clean_sector_waits_for_the_write_back`;
[`test_lower_errors.py`](../../tests/test_lower_errors.py): `test_failed_write_is_reported`,
`test_writes_fail_while_reads_go_on`, `test_a_cache_full_of_failed_chunks_refuses_writes`;
[`test_discard.py`](../../tests/test_discard.py): `test_data_in_the_cache_is_dropped_by_a_discard`.

## The sync

```mermaid
sequenceDiagram
    participant Up as Flushes from above
    participant W as Worker
    participant Bm as Bitmap
    participant Low as Lower device
    Up->>W: empty flush or FUA write
    W->>Low: write back everything dirty, wait
    W->>Low: flush
    Note over Low: the data written back is durable
    W->>Bm: next generation of each changed block
    W->>Low: first copy of each changed block
    W->>Low: flush
    Note over Low: a bit on the device means durable data
    W-->>Up: complete, with an error if an entry or a block failed
    W->>Low: trailing metadata of the chunks written back
    W->>Low: second copy of each changed block
    W->>Low: flush
    Note over Low: both copies durable before the next write back
```

Covered by [`test_durability.py`](../../tests/test_durability.py) (all);
[`test_metadata.py`](../../tests/test_metadata.py): `test_the_trailing_copy_is_written_after_a_flush`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_bit_reaches_the_device_only_with_a_flush`,
`test_a_flush_fails_when_the_first_copy_of_a_block_fails_to_write`, `test_a_second_copy_that_fails_to_write_is_counted`;
[`test_crash.py`](../../tests/test_crash.py): `test_flushed_writes_survive_a_crash`.

## A crash between the two copies

What a sector holds after a crash at each point of a write back of new data over old, and what reads.

```mermaid
stateDiagram-v2
    direction LR
    steady: data old, leading old, trailing old
    leadnew: data old, leading NEW, trailing old
    datanew: data NEW, leading NEW, trailing old
    settled: data NEW, leading NEW, trailing NEW
    [*] --> steady
    steady --> leadnew: leading sector with FUA
    leadnew --> datanew: data written, flush
    datanew --> settled: trailing copy after the flush
    note right of leadnew: old data matches the trailing copy, reads old
    note right of datanew: new data matches the leading copy, reads new
```

A crash in any state leaves each sector readable, as old or new. Not covered: a crash in the middle states
together with a lost sector of the copy that matches.

Covered by [`test_crash.py`](../../tests/test_crash.py): `test_a_write_cut_between_data_and_metadata_reads_old_or_new`,
`test_chunks_of_a_region_cut_between_flushes_read_old_or_new_each`, `test_ext4_survives_a_crash_after_each_fsync`,
`test_ext4_survives_a_crash_at_any_flush`.

## Before a write back: barrier and settle

```mermaid
flowchart TD
    start(["Entry picked for write back"]) --> since{"Chunk written back since the last flush?"}
    since -- yes --> barrier["Barrier: wait for the jobs, sync"]
    since -- no --> clear{"Bit clear while a clear of a discard is not yet synced?"}
    clear -- yes --> barrier
    clear -- no --> unwritten
    barrier --> unwritten{"Bit of the chunk clear?"}
    unwritten -- "yes, and the clears are synced" --> whole["First write back: whole chunk, zeros around the data, no settle"]
    unwritten -- no --> differ{"Copies differ in the sectors to write?"}
    unwritten -- "yes, but the sync failed: settled as written" --> differ
    differ -- no --> jobs(["Send the jobs"])
    differ -- yes --> settle["Settle: read the chunk"]
    settle --> match{"Each such sector matches"}
    match -- "the leading copy" --> fua["Write that CRC into the trailing copy with FUA"]
    match -- "the trailing copy" --> jobs
    match -- "neither" --> count["Count a mismatch, leave it visible"]
    fua --> jobs
    count --> jobs
    whole --> jobs
```

Covered by [`test_crash.py`](../../tests/test_crash.py):
`test_a_chunk_written_back_twice_between_flushes_reads_one_of_its_versions`,
`test_a_second_crash_after_one_between_the_copies`, `test_first_writes_cut_anywhere_read_zeros_or_new`,
`test_a_write_after_a_discard_cut_anywhere_reads_zeros_or_new`;
[`test_corruption.py`](../../tests/test_corruption.py): `test_a_sector_whose_copies_differ_is_read_before_it_is_written`,
`test_only_the_sectors_written_are_read_first`, `test_a_sector_matching_neither_copy_is_counted_before_it_is_written`;
[`test_discard.py`](../../tests/test_discard.py): `test_a_write_after_a_discard_is_written_whole_after_a_barrier`,
`test_a_second_write_after_a_flushed_discard_needs_no_barrier`.

## The bitmap: choosing a copy of a block

```mermaid
flowchart TD
    start(["First resume: both copies of a block read"]) --> lv{"Leading copy valid? CRC from the salt, group, index, role"}
    lv -- yes --> both{"Trailing copy valid too?"}
    lv -- no --> tv{"Trailing copy valid?"}
    both -- yes --> newer["Take the one with the larger generation"]
    both -- no --> single["Take the leading one, repair the other with the next flush"]
    tv -- yes --> single2["Take the trailing one, repair the other with the next flush"]
    tv -- no --> ro["Read only range: chunks read as written, CRC decides, writes and discards fail"]
```

Covered by [`test_bitmap.py`](../../tests/test_bitmap.py): `test_one_damaged_copy_is_covered_and_repaired`,
`test_the_copy_with_the_larger_generation_is_taken`, `test_a_block_of_another_place_or_device_is_not_taken`,
`test_a_block_invalid_in_both_copies_makes_its_range_read_only`, `test_a_discard_touching_a_read_only_block_fails_whole`,
`test_a_reload_keeps_the_bits_the_old_table_sets`; [`test_lost_writes.py`](../../tests/test_lost_writes.py):
`test_a_lost_copy_of_a_block_of_the_bitmap_is_covered_by_the_other`.

## Discard and its trap

```mermaid
sequenceDiagram
    participant Up as Layer above
    participant Map as dm_map
    participant W as Worker
    participant Low as Lower device
    Up->>Map: discard
    alt no whole chunk
        Map-->>Up: complete at once
    else touches a read only range
        Map-->>Up: error
    else
        Map->>W: queue it
        W->>W: wait for the write backs in flight
        W->>W: drop the entries of its whole chunks, clear their bits, count a clear
        W-->>Up: complete - nothing written below
    end
    Note over Low: the bit is still set on the device until the next sync
    Up->>Map: write to a discarded chunk
    W->>W: first write back while a clear is not synced
    W->>Low: barrier - sync, the cleared bit reaches the device
    W->>Low: whole chunk, leading copy with FUA, then the data
    Note over Low: a crash now reads zeros, never a chunk that matches neither copy
```

Covered by [`test_discard.py`](../../tests/test_discard.py) (all); [`test_crash.py`](../../tests/test_crash.py):
`test_a_discard_cut_anywhere_reads_old_or_zeros`, `test_a_write_after_a_discard_cut_anywhere_reads_zeros_or_new`;
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_discard_touching_a_read_only_block_fails_whole`.

## Failures of the lower device

```mermaid
flowchart LR
    subgraph reads["A read fails"]
        rd["data sector"] --> rdo["only the bios over it fail"]
        rm1["metadata sector, one copy"] --> rm1o["taken from the other copy, warned"]
        rm2["metadata sector, both copies"] --> rm2o["its 8 chunks fail, reads and writes"]
    end
    subgraph writes["A write fails"]
        wd["write back"] --> wdo["entry FAILED, data kept, flushes fail, retried"]
        wf["every write back"] --> wfo["cache fills with failed entries, new writes refused, reads go on"]
        wt["trailing metadata"] --> wto["counted, the leading copy carries on"]
        wb["first copy of a bitmap block"] --> wbo["the flush fails, the block stays dirty"]
    end
```

Covered by [`test_lower_errors.py`](../../tests/test_lower_errors.py) (all);
[`test_bitmap.py`](../../tests/test_bitmap.py): `test_a_flush_fails_when_the_first_copy_of_a_block_fails_to_write`,
`test_a_second_copy_that_fails_to_write_is_counted`.

## Lost writes

A write acknowledged by the lower device and never on its medium.

```mermaid
flowchart TD
    lost(["A write back, partly lost"]) --> what{"What was lost?"}
    what -- "data of a rewrite" --> a1["Before the flush: the old data reads, the trailing copy matches it"]
    a1 --> a2["After the flush: both copies hold the new CRC, the chunk fails"]
    what -- "data of a first write" --> b1["Fails at once: zeros below match neither copy, through the seed"]
    what -- "the leading metadata sector" --> c1["The trailing copy covers it, the next write back settles it"]
    what -- "one copy of a bitmap block" --> d1["The other copy, of the newer generation, is taken"]
    what -- "data and both metadata copies" --> e1["The old data passes, for ever: the blind spot, for the parity of the correction stage"]
```

Covered by [`test_lost_writes.py`](../../tests/test_lost_writes.py) (all); the seed by
[`test_corruption.py`](../../tests/test_corruption.py): `test_zeroed_chunk_is_detected`,
`test_chunk_copied_elsewhere_is_detected`, `test_sectors_swapped_inside_a_chunk_with_their_crcs_are_detected`,
`test_a_zeroed_region_with_its_chunks_written_is_detected`, `test_a_region_shifted_whole_with_its_metadata_is_detected`,
`test_a_chunk_from_another_device_is_detected`.
