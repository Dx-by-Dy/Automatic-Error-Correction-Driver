# Diagrams

The situations of [ARCHITECTURE.md](ARCHITECTURE.md) as pictures, each with the tests that cover it. The terms are
in the [glossary](ARCHITECTURE.md#glossary); the tests are described in [TESTS.md](TESTS.md), and live in
[`tests/`](../../tests). `tools/check-docs.py` checks that every diagram here parses. What the driver does wrong
today, each case a strict `xfail`, is drawn at the end, in [Cases that fail today](#cases-that-fail-today).

## The stack

```mermaid
flowchart TB
    fs["Filesystem or application"]
    subgraph driver["dm-dcorr"]
        map["dcorr_map: waits if it must, never for its own lower bio"]
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
    valid0 -- no --> probe["Probe the start of group 1 for every size, from 16 MiB to 4 GiB: the first valid copy wins"]
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
The probe takes a copy stored as data as well: [The probe takes a copy stored as
data](#the-probe-takes-a-copy-stored-as-data).

## The write path

```mermaid
sequenceDiagram
    participant Up as Layer above
    participant Map as dcorr_map
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
    crc -- yes --> only{"A sector matched only the leading copy, the chunk not written back since the flush?"}
    only -- yes --> settle["Hand the chunk to the worker to settle"]
    only -- no --> ok(["Complete"])
    settle --> ok
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
[`test_lower_errors.py`](../../tests/test_lower_errors.py): `test_failed_data_sector_fails_only_its_reads`;
[`test_lost_writes.py`](../../tests/test_lost_writes.py): `test_old_data_put_back_fails_once_the_new_was_read`;
[`test_crash.py`](../../tests/test_crash.py): `test_a_second_crash_after_one_between_the_copies`.

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
        clean sectors wait in dcorr_map
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

The same sync runs for a barrier, when half the metadata areas are busy, and on a suspend. If the first flush
fails, the flushes from above fail and no trailing copy is written; the chunks written back stay pinned for the
next sync: [A failed flush of the lower device](#a-failed-flush-of-the-lower-device).

## A failed flush of the lower device

```mermaid
sequenceDiagram
    participant W as Worker
    participant M as Metadata in RAM
    participant Low as Lower device
    W->>Low: write back of chunk A, version 2: leading copy with FUA, then the data
    W->>M: A written since the flush, its area pinned
    W->>Low: flush
    Low-->>W: fails
    Note over M: the area stays pinned, A still counts as written since the flush
    W->>W: next write back of A, version 3: a barrier first
    W->>Low: flush
    alt the flush fails again
        Low-->>W: fails
        W->>W: the write back is given up, A keeps version 3 in RAM, the flushes fail
    else the flush succeeds
        Low-->>W: done, version 2 durable
        W->>Low: the trailing copy of A takes version 2, then leading version 3 and the data
    end
```

Covered by [`test_lower_errors.py`](../../tests/test_lower_errors.py):
`test_a_chunk_written_back_again_after_a_failed_flush_takes_a_barrier`, a barrier with a failed flush between the
two write backs as with none, and `test_a_chunk_whose_barrier_fails_is_not_written_back`.

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

A crash in any state leaves each sector readable, as old or new. A crash in the middle states together with a
lost sector of the copy that matches fails the chunk while the sector does not read, by decision, and a write of a
neighbour does not make it permanent: [A metadata sector rebuilt from one copy](#a-metadata-sector-rebuilt-from-one-copy). A crash after the flush from
above and before the trailing copy leaves the state with the new data; the first read of it, which matches only
the leading copy, hands the chunk to the worker to settle, see [The read path](#the-read-path).

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
    both -- yes --> newer["Take the one with the larger generation; an older one is rewritten with the next flush"]
    both -- no --> single["Take the leading one, repair the other with the next flush"]
    tv -- yes --> single2["Take the trailing one, repair the other with the next flush"]
    tv -- no --> ro["Read only range: chunks read as written, CRC decides, writes and discards fail"]
```

Covered by [`test_bitmap.py`](../../tests/test_bitmap.py): `test_one_damaged_copy_is_covered_and_repaired`,
`test_the_copy_with_the_larger_generation_is_taken`, `test_a_block_of_another_place_or_device_is_not_taken`,
`test_a_block_invalid_in_both_copies_makes_its_range_read_only`, `test_a_discard_touching_a_read_only_block_fails_whole`,
`test_a_reload_keeps_the_bits_the_old_table_sets`; [`test_lost_writes.py`](../../tests/test_lost_writes.py):
`test_a_lost_copy_of_a_block_of_the_bitmap_is_covered_by_the_other`, and for the older copy rewritten
`test_an_older_copy_is_rewritten_before_the_newer_is_lost`. What a read only range gives for a chunk zeroed
before: [A zeroed chunk in a read only range](#a-zeroed-chunk-in-a-read-only-range).

## Discard and its trap

```mermaid
sequenceDiagram
    participant Up as Layer above
    participant Map as dcorr_map
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

## Write zeroes

```mermaid
flowchart TD
    wz(["Write zeroes over sectors 3 of chunk 4 to 5 of chunk 7"]) --> offered{"Has the lower device write zeroes?"}
    offered -- no --> writes["not offered: the kernel writes zero pages, ordinary writes through the cache"]
    offered -- yes --> ro{"Touches a read only range?"}
    ro -- yes --> fail["refused"]
    ro -- no --> ends["partial chunks 4 and 7: zeros written into their entries, as a write"]
    ends --> whole["whole chunks 5 and 6: to the worker as a discard, entries dropped, bits cleared"]
    whole --> done["completed; zeros read from the cache and without a read below"]
    done --> durable["durable after the next flush, as a write"]
```

Covered by [`test_discard.py`](../../tests/test_discard.py): `test_the_device_offers_discard_in_chunks_and_write_zeroes`,
`test_write_zeroes_reads_zeros_and_keeps_the_neighbours`, `test_write_zeroes_survives_recreating_the_device`,
`test_write_zeroes_over_data_in_the_cache`, `test_blkdiscard_z_zeroes_through_write_zeroes`,
`test_write_zeroes_inside_one_chunk_zeroes_only_its_sectors`; [`test_lower_errors.py`](../../tests/test_lower_errors.py):
`test_write_zeroes_is_not_offered_over_a_lower_device_without_it`.

## Failures of the lower device

```mermaid
flowchart LR
    subgraph reads["A read fails"]
        rd["data sector"] --> rdo["only the bios over it fail"]
        rm1["metadata sector, one copy"] --> rm1o["taken from the other copy, warned; checked before it is written over"]
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
`test_a_second_copy_that_fails_to_write_is_counted`. A metadata sector failed in one copy after a crash: [A
metadata sector rebuilt from one copy](#a-metadata-sector-rebuilt-from-one-copy); a failed flush: [A failed
flush of the lower device](#a-failed-flush-of-the-lower-device).

## A metadata sector rebuilt from one copy

```mermaid
flowchart TD
    load["A copy of a metadata sector fails to read: filled in RAM from the other, marked filled"] --> due["A write of the sector from RAM is due: leading by a write back, trailing by a sync or a settle"]
    due --> again{"The failed copy reads again?"}
    again -- yes --> take["Taken into RAM, the sector written as usual"]
    again -- no --> check["Each chunk of the sector read and compared with the copy that reads"]
    check --> match{"All match? Left out: what the write covers, chunks written since the flush, never written, parity"}
    match -- yes --> wr["The sector written from RAM"]
    match -- no --> which{"Which copy?"}
    which -- leading --> fail["The write back fails, its entry kept; the neighbours wait until the sector reads or the chunk is rewritten whole"]
    which -- trailing --> skip["The trailing sector left, counted in trail_errors"]
```

After a crash in a write back the copies of a chunk differ and its data matches only one of them; if that copy
fails to read, writing the sector from RAM would put the other CRC on the device and fail the chunk for good.
Covered by [`test_lower_errors.py`](../../tests/test_lower_errors.py):
`test_a_sector_rebuilt_from_one_copy_keeps_its_neighbours_readable`, with the leading copy failed after a crash
after the data, the write back of a neighbour failing until the sector heals; with the trailing copy failed after
a crash before the data, the neighbour written and the trailing sector left; with the copies equal, and with the
failed copy reading again, the neighbour written.

## Every error is a signal

```mermaid
flowchart LR
    err(["An error: a failed read, write back or flush, a CRC mismatch, metadata or bitmap"]) --> cnt["its counter in dmsetup status grows"]
    err --> log["a line in the kernel log: the name from dmsetup, the logical sector; rate limited, one limit for all devices"]
    err --> first{"The first since the table was created?"}
    first -- yes --> ev["a work item raises a device mapper event"]
    ev --> wait["dmsetup wait, dmeventd: the user reads the counters and moves the data off"]
    first -- no --> none["no event"]
```

Covered by [`test_lower_errors.py`](../../tests/test_lower_errors.py):
`test_the_first_error_raises_one_device_mapper_event`, `test_a_failed_read_is_counted_and_logged_with_the_device`,
`test_a_failed_metadata_read_is_counted_in_sectors`, `test_a_failed_flush_is_counted`,
`test_failed_write_is_reported`; [`test_corruption.py`](../../tests/test_corruption.py):
`test_every_damaged_sector_of_a_read_is_counted_and_logged`,
`test_a_flood_of_mismatches_is_counted_whole_and_logged_rate_limited`. The limit of each place in the code is
shared by all devices, so a flood on one hides the first errors of another for 5 s: strict `xfail`
`test_a_flood_on_one_device_does_not_hide_the_errors_of_another`.

## Lost writes

A write acknowledged by the lower device and never on its medium.

```mermaid
flowchart TD
    lost(["A write back, partly lost"]) --> what{"What was lost?"}
    what -- "data of a rewrite" --> a1["Before the flush: the old data reads, the trailing copy matches it"]
    a1 --> a2["After the flush: both copies hold the new CRC, the chunk fails"]
    what -- "data of a first write" --> b1["Fails at once: zeros below match neither copy, through the seed"]
    what -- "the leading metadata sector" --> c1["The trailing copy covers it, the next write back settles it"]
    what -- "the trailing metadata sector, or a crash before it" --> t1["The old CRC stays until the chunk is read or written back; a read of the new data settles it, and the old data put back fails"]
    what -- "one copy of a bitmap block" --> d1["The other copy, of the newer generation, is taken"]
    what -- "data and both metadata copies" --> e1["The old data passes, for ever: the blind spot, for the parity of the correction stage"]
```

Covered by [`test_lost_writes.py`](../../tests/test_lost_writes.py) (all); the seed by
[`test_corruption.py`](../../tests/test_corruption.py): `test_zeroed_chunk_is_detected`,
`test_chunk_copied_elsewhere_is_detected`, `test_sectors_swapped_inside_a_chunk_with_their_crcs_are_detected`,
`test_a_zeroed_region_with_its_chunks_written_is_detected`, `test_a_region_shifted_whole_with_its_metadata_is_detected`,
`test_a_chunk_from_another_device_is_detected`.

## Cases that fail today

Found by the review of `src/` on 2026-11-17, each pinned by a strict `xfail` with its item in [TODO.md](TODO.md);
the diagram shows the path to the wrong result. A positive control of each test passes.

### A zeroed chunk in a read only range

```mermaid
flowchart TD
    w["Chunk written and flushed: data OLD, both copies of its CRCs those of OLD, bit set"] --> z["Discard or write zeroes: the bit cleared, nothing written below"]
    z --> r1["Reads zeros"]
    r1 --> lost["Both copies of its block of the bitmap become invalid"]
    lost --> ro["Read only range: every chunk read as written, the CRC decides"]
    ro --> wrong["OLD below matches its old CRCs: OLD returned with no error, where zeros or an error are right"]
```

Pinned by `test_a_zeroed_chunk_in_a_read_only_block_never_reads_its_old_data`, for discard and write zeroes.

### The probe takes a copy stored as data

```mermaid
flowchart TD
    fmt["Formatted with groups of 32 MiB: group 1 starts at 32 MiB"] --> img["The image of a superblock of group 1 for groups of 16 MiB stored as data, at 16 MiB, inside group 0"]
    img --> dmg["Group 0 damaged"]
    dmg --> p16["The probe tries 16 MiB first: the image is valid for that place"]
    p16 --> wrong["The layout of 16 MiB taken"]
    wrong --> refused["The table length is not its capacity: refused"]
    p16 -. "never read" .-> truecopy["The true copy at 32 MiB"]
```

Pinned by `test_a_superblock_stored_as_data_does_not_win_the_probe`. With a table for the layout of the image the
device would come up over the wrong layout.

### Two devices on one lower device

```mermaid
flowchart LR
    a["Device A: its cache, metadata and bitmap in RAM"] -- "first write of chunk C, flush: the bit set" --> low[("One lower device")]
    b["Device B: its bitmap read at its own resume, before"] -- "read of C" --> zeros["no bit for C in RAM: zeros, with no lower read and no error"]
    a -. "each writes its own bitmap over the other" .- b
```

Pinned by `test_a_second_device_on_the_same_lower_device_is_refused_or_agrees`: device mapper takes the second
table, so the second device reads zeros where the first wrote.
