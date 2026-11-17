# Showing the driver

A sequence of commands to show the driver to another developer: building it, creating a device, its status, and
what it does with a sector damaged behind its back. Run them **only in the development VM** of
[DEPLOY.md](docs/en/DEPLOY.md): they overwrite `/dev/vdb`. The outputs quoted are those of a test disk of 2 GiB,
the default.

## 0. Enter the VM

On the host:

```bash
deploy/vm.sh start
deploy/vm.sh sync          # copy the working tree into the VM
deploy/vm.sh ssh
```

In the VM:

```bash
sudo -i
cd ~as/corrdm
```

## 1. Build and load

```bash
make
modprobe dm-mod
insmod dm-dcorr.ko
lsmod | grep dm_dcorr
dmsetup targets | grep dcorr
```

## 2. Format and create the device

The disk is filled with garbage first, to show that it need not be zeroed.

```bash
dd if=/dev/urandom of=/dev/vdb bs=1M count=64 oflag=direct status=none
tools/dcorrsetup format --force /dev/vdb
tools/dcorrsetup dump /dev/vdb          # the superblock and the layout: salt, groups, capacity
tools/dcorrsetup table /dev/vdb         # 0 3809280 dcorr /dev/vdb
tools/dcorrsetup table /dev/vdb | dmsetup create dcorr
dmsetup table dcorr                     # the lower device as major:minor
blockdev --getsize64 /dev/vdb /dev/mapper/dcorr    # 2 GiB below, about 1.8 GiB on top
```

## 3. Status

`dmsetup status` prints 26 counters in a row, described in
[the interface](docs/en/ARCHITECTURE.md#interface). A function to print them with their names:

```bash
names=(map_waits free_waits busy_waits read_waits dirty failed metadata_loads metadata_waits trail_errors
       crowded_flushes barriers settle_reads settle_mismatches unwritten_reads read_only_blocks single_blocks
       bad_superblocks bitmap_write_errors refused_writes discards discarded_chunks read_errors crc_mismatches
       write_errors metadata_read_errors flush_errors)
st() { local v=($(dmsetup status dcorr)); for i in "${!names[@]}"; do printf '%-22s %s\n' "${names[i]}" "${v[i+3]}"; done; }

dmsetup status dcorr
st
```

`unwritten_reads` is not zero right after the device is created: udev and blkid have read it.

## 4. Chunks never written read as zeros

```bash
dd if=/dev/mapper/dcorr bs=1M count=1 iflag=direct status=none | hexdump -C | head -3   # all zeros
st | grep -w unwritten_reads                                                          # grows
```

## 5. Writes go through the cache

```bash
dd if=/dev/urandom of=/tmp/pattern bs=4K count=256 status=none
dd if=/tmp/pattern of=/dev/mapper/dcorr bs=4K oflag=direct status=none; st | grep -w dirty   # 256
sleep 2; st | grep -w dirty                                                                  # 0: written back
sync /dev/mapper/dcorr                                                                       # a flush
cmp <(dd if=/dev/mapper/dcorr bs=4K count=256 iflag=direct status=none) /tmp/pattern && echo same
```

## 6. A sector damaged below the driver

In a **second window**, wait for the event of the device:

```bash
dmsetup wait dcorr $(dmsetup info -c --noheadings -o events dcorr); echo "event"
```

In the first one, find the lower sector that holds logical sector 10, check it, and overwrite it behind the
back of the driver:

```bash
P=$(python3 -c 'import sys; sys.path.insert(0, "tests"); from harness import physical_sector, DEFAULT_GROUP_SECTORS; print(physical_sector(10, int(sys.argv[1]), DEFAULT_GROUP_SECTORS))' $(blockdev --getsz /dev/vdb))
cmp <(dd if=/dev/vdb bs=512 skip=$P count=1 iflag=direct status=none) <(dd if=/tmp/pattern bs=512 skip=10 count=1 status=none) && echo "lower sector $P holds logical 10"

dd if=/dev/urandom of=/dev/vdb bs=512 seek=$P count=1 oflag=direct status=none
```

Read it and its neighbours:

```bash
dd if=/dev/mapper/dcorr of=/dev/null bs=512 skip=10 count=1 iflag=direct          # Input/output error
dd if=/dev/mapper/dcorr of=/dev/null bs=512 skip=9  count=1 iflag=direct status=none && echo "sector 9 ok"
dd if=/dev/mapper/dcorr of=/dev/null bs=512 skip=11 count=1 iflag=direct status=none && echo "sector 11 ok"
st | grep -w crc_mismatches     # 1
dmesg | tail -1                 # CRC mismatch in 1 of 1 sectors read at sector 10
```

The second window prints `event`: the first error raised it.

## 7. A write puts the sector right

```bash
dd if=/tmp/pattern of=/dev/mapper/dcorr bs=512 skip=10 seek=10 count=1 oflag=direct status=none
sync /dev/mapper/dcorr
dd if=/dev/mapper/dcorr of=/dev/null bs=512 skip=10 count=1 iflag=direct status=none && echo "sector 10 ok again"
```

## 8. A filesystem on top

```bash
mkfs.ext4 -q /dev/mapper/dcorr
mkdir -p /mnt/dcorr && mount /dev/mapper/dcorr /mnt/dcorr
cp -r /usr/share/doc /mnt/dcorr/ && sync && df -h /mnt/dcorr
umount /mnt/dcorr
```

## 9. Remove it

```bash
dmsetup remove dcorr
rmmod dm_dcorr
```

## Traps

- **Damage a whole sector with `oflag=direct`.** A buffered `dd` of a few bytes into `/dev/vdb` writes back the
  whole page of 4 KiB from the page cache of `vdb`, which still holds what was there before the format: the
  neighbouring sectors are damaged too, and the read of sector 9 or 11 fails as well.
- **Pass the size of the group.** `physical_sector` of `tests/harness.py` takes the group of 16 MiB the tests
  use unless told otherwise; `dcorrsetup format` makes groups of 1 GiB by default, so `DEFAULT_GROUP_SECTORS` is
  passed, or the sector found is the wrong one. The `cmp` before the damage checks it.
