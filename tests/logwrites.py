"""The log of dm-log-writes: reading it and replaying a prefix of it.

dm-log-writes passes the I/O through to its device and logs every write on a second device. A
write is logged once a flush covers it, or at once if it is FUA, so the log is in the order the
data reaches the disk itself, not its cache. Replaying a prefix of the log to a zeroed device
gives the state the disk would be in after a crash at that point.

The format, from drivers/md/dm-log-writes.c: a super block in sector 0, then for each entry one
block with its header (and the text of a mark), followed by the data of a write. Blocks have the
logical block size of the device, sectors in the header are counted in such blocks. This is also
what replay-log of xfstests reads.
"""

import struct
from dataclasses import dataclass

MAGIC = 0x6A736677736872
VERSION = 1
SUPER = struct.Struct("<QQQI")
ENTRY = struct.Struct("<QQQQ")

FLUSH = 1 << 0
FUA = 1 << 1
DISCARD = 1 << 2
MARK = 1 << 3


@dataclass
class Entry:
    index: int
    sector: int  # in 512-byte sectors
    flags: int
    data: bytes  # what a write wrote, empty for the rest
    mark: str | None


def read_log(path):
    """The entries of a log, in order."""
    with open(path, "rb") as log:
        magic, version, count, block_size = SUPER.unpack(log.read(SUPER.size))
        assert magic == MAGIC and version == VERSION, f"not a dm-log-writes log: {magic:#x} {version}"
        scale = block_size // 512
        entries = []
        position = block_size
        for index in range(count):
            log.seek(position)
            block = log.read(block_size)
            sector, blocks, flags, data_len = ENTRY.unpack_from(block)
            mark = block[ENTRY.size : ENTRY.size + data_len].decode() if flags & MARK else None
            position += block_size
            data = b""
            if blocks and not flags & DISCARD:
                data = log.read(blocks * block_size)
                assert len(data) == blocks * block_size, "the log ends inside an entry"
                position += blocks * block_size
            entries.append(Entry(index, sector * scale, flags, data, mark))
        return entries


def mark_index(entries, name):
    """The index of the entry of a mark, so that entries[:index + 1] is the state at it."""
    for entry in entries:
        if entry.mark == name:
            return entry.index
    raise AssertionError(f"no mark {name} in the log")


def replay(entries, device):
    """Writes the data of the entries to a zeroed BlockDevice, in order."""
    for entry in entries:
        assert not entry.flags & DISCARD, "the device under test does not discard"
        if entry.data:
            device.write(entry.sector, entry.data)
