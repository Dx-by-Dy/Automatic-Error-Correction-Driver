# TODO

How the driver works is in [README.md](README.md) and `docs/`; how to build and
run it is in [deploy/README.md](deploy/README.md); the tests are described in
[correction-driver/tests/README.md](correction-driver/tests/README.md). This file holds only what is
not done yet.
The order of work is in [Stages](#stages), at the end.

How to keep this file:

- Remove an item once it is done; the history is in git. How the driver works belongs in `README.md`
  and `docs/`, not here.
- Group items by topic under `##` headings. Start an item with a short bold statement of the problem,
  then give the cause, the consequence and a way to fix it, if known.
- Say how a problem is known, as below. Do not promote an item to **Confirmed** without a run.
- `## Stages` stays the last section and gives the order of work. Update it when items are added or
  finished.

Problems below were found at commit `086ef3c`, on Fedora 45 with kernel
`7.2.15+debug`, a virtio disk as `/dev/vdb`. **Confirmed** means it was observed
in a run, **From reading** means it was only found in the code.

## Integrity and durability

- **`fsync` does not reach the lower device.** Confirmed: `vdb` is `write back`, the dm device is
  `write through`. An `fsync` on the dm device gives 0 flush bios on `vdb`, the same `fsync` on
  `vdb` itself gives 1. A filesystem believes its data is durable while it is in the lower
  device's cache. `num_flush_bios` is not set, and the `REQ_OP_FLUSH` branch in `dm_map` is
  dead code, since a flush arrives as an empty `REQ_OP_WRITE` with `REQ_PREFLUSH`. Fix: enable
  flushes, handle the empty bio, carry FUA over to both the data and the metadata.
- **A zeroed chunk passes the check.** Confirmed: with a chunk and its metadata sector zeroed
  on the lower device, the read succeeds and returns zeros. CRC64 of zeros with a zero seed is
  0, the same as empty metadata. A lost or trimmed region is never noticed. Fix: a non-zero
  seed, plus a way to tell unwritten chunks from written ones (see the next item).
- **A fresh device has to be zeroed by hand.** From reading: there is no superblock, format
  version or "never written" state. On a device with old contents every read fails, and
  `deploy/vm.sh reinit` zeroes only the first 1 GiB.
- **The CRC does not depend on the position.** Confirmed: a chunk copied with its metadata over
  another chunk reads back without an error, as the sector number is not part of the CRC. A
  misdirected write would pass the same way. Fix: mix the sector number into the seed.
- **Data and CRC are not written atomically.** From reading: they are two independent bios, so
  after a power loss a chunk may have new data and an old CRC, and reads fail on data that
  is fine. It is the same when the metadata bio of a partial write fails after its data bio
  succeeded. Needs a decision (journal, or tolerate and resolve through ECC) and a crash test
  with `dm-log-writes`.
- **Pages can change after their CRC is computed.** From reading, with `stable_writes=0`
  confirmed: the CRC is computed in `dm_map` and the pages are submitted later, without a copy.
  A page changed in between (`mmap`, a buffer in use during O_DIRECT) gives a CRC that does not
  match the data, then a false mismatch on read. Fix: request stable writes in `io_hints` and
  check it is enough, or write from a copy.
- **Other request types bypass the CRC.** From reading: the `REQ_OP_DISCARD` and `default`
  branches in `dm_map` only remap the start sector, so a range would also cover metadata sectors.
  They do not run today (`discard_max_bytes=0` confirmed). Either remove them, or implement
  discard along with the "never written" state.

## Device Mapper integration

- **`dmsetup table` does not show the device.** Confirmed: it prints `0 14913080 corrdm` with no
  arguments, as `.status` gives nothing for `STATUSTYPE_TABLE`, so the table cannot be saved and
  reloaded. `dmsetup status` has a single counter, the waits for a place among the parts in flight;
  counters such as CRC mismatches do not exist yet.
- **The table length is ignored.** Confirmed: `dm_ctr` overwrites `ti->len` (16777216 requested,
  14913080 used). Fix: require a correct length, return an error otherwise, and print the
  right value with a helper command.
- **Queue limits are not inherited.** From reading: there is no `.iterate_devices` or `.io_hints`.
  A lower device with 4K logical blocks is not rejected, although metadata is written
  as single 512-byte sectors.
- **Mismatch logging has no rate limit.** From reading: each failed read prints a line with
  `pr_err`, so a reader in a loop can flood the log. The line also gives the physical sector,
  and nothing identifies the device.

## Correction

The goal of the project; only detection exists today.

- **No design yet:** which code, what it corrects (bits, a sector, a whole chunk), where the
  redundancy lives and how much space it takes, and how it combines with the CRC.
- **Recovery path:** the entry point is marked in `check_crc`. It needs a retry of the read,
  rewriting the fixed data, and counters. The clone of a chunk is ours until `bio_endio`, with its
  iterator saved in `saved_iter`, so a read can be submitted again from `complete_work`.

## Optimization and cleanup

Carried over from the previous list.

- **Benchmarks are not formalized.** `benchmarks.py` has hardcoded devices, test sets commented
  in and out by hand, and needs `pandas` and `matplotlib`. Numbers need a non-debug kernel.
- **Move `first_sector` and `nr_sectors` into `struct trn_p_rq`.**
- **Use preallocation where possible.**
- **Use the Crypto API to speed up CRC64.**
- **Cache hot metadata blocks** (a lock on the cache and a state machine).

## Tests and tooling

- **Tests that do not exist yet:**
  - lower device errors, through `dm-flakey` and `dm-dust`;
  - lifecycle: removal under load, unloading the module, leaks through kmemleak;
  - crash consistency: `dm-log-writes`.

## Documentation

- **The README uses the wrong target name.** Confirmed: it says `correction_driver`, the target is
  `corrdm`, so its `dmsetup create` command fails. It also passes a length that is not used.
- **The README claims functional testing is done**, and does not mention the VM.
- **`MODULE_DESCRIPTION` says "Linux Kernel 6.16"**, while the driver builds on 7.1 and 7.2.

## Open questions

- Should a CRC cover a 512-byte sector or the whole 4 KiB chunk? Per sector takes 64 bytes per chunk
  and can tell which sector is bad, which matters for correction.
- Should metadata stay next to the data? It makes a metadata write a seek and splits
  sequential I/O; a separate area would change the on-disk format, so decide before ECC.

## Stages

1. **Trustworthy tests.** Data, corruption, filesystem, fio and target tests are in place, known bugs
   are strict `xfail` or `known_hang`, `make check` is clean. What is left: lower device errors,
   lifecycle.
2. **Integrity and durability.** Flushes first, as they lose data today; then stable pages, seed and
   position in the CRC, the on-disk format, crash tests.
3. **Device Mapper integration and docs.** `.status` with the table and more counters, table length, queue limits,
   the README.
4. **Baseline.** Formalize the benchmarks and take numbers on a non-debug kernel, to compare the
   later stages against.
5. **Correction.** Settle the open questions, design the code and the format, implement recovery.
6. **Optimization.** Metadata cache, preallocation, Crypto API, tuning the limit on parts in flight,
   guided by the baseline.
