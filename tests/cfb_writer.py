# SPDX-License-Identifier: MIT
"""Minimal writer for OLE compound files ([MS-CFB]) used to build MSI-like test files.

Sectors of different streams are allocated round-robin, so every stream larger than one
sector is fragmented: its bytes are NOT contiguous in the file. This is what defeats naive
byte carving and what emudhra_scan.cfb_signature_streams must undo.
"""
import struct

ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF
MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _ceil(a, b):
    return (a + b - 1) // b


def _interleave(chains):
    """Allocate one unit to each chain in turn. chains: list of unit counts -> list of index lists."""
    out = [[] for _ in chains]
    nxt, remaining = 0, list(chains)
    while any(remaining):
        for i, r in enumerate(remaining):
            if r:
                out[i].append(nxt)
                nxt += 1
                remaining[i] -= 1
    return out, nxt


def build(streams, version=3, cutoff=4096):
    """streams: list of (name, bytes). Returns the compound file as bytes."""
    ss = 512 if version == 3 else 4096
    mss = 64
    per = ss // 4
    big = [(n, d) for n, d in streams if len(d) >= cutoff]
    small = [(n, d) for n, d in streams if len(d) < cutoff]

    # Mini stream: mini sectors of small streams interleaved.
    mini_alloc, nmini = _interleave([_ceil(len(d), mss) for _, d in small])
    ministream = bytearray(nmini * mss)
    minifat = [FREESECT] * nmini
    for (name, d), units in zip(small, mini_alloc):
        for k, u in enumerate(units):
            ministream[u * mss:u * mss + mss] = d[k * mss:(k + 1) * mss].ljust(mss, b"\x00")
            minifat[u] = units[k + 1] if k + 1 < len(units) else ENDOFCHAIN
    nminifat_secs = _ceil(len(minifat) * 4, ss) if minifat else 0

    entries = 1 + len(streams)
    ndir = _ceil(entries, ss // 128)

    # Regular sectors: big streams and the mini stream container interleaved.
    data_chains = [_ceil(len(d), ss) for _, d in big] + ([_ceil(len(ministream), ss)] if ministream else [])
    alloc, ndata = _interleave(data_chains)

    nfat = 1
    while nfat * per < nfat + ndir + nminifat_secs + ndata:
        nfat += 1
    assert nfat <= 109, "test files must not need DIFAT sectors"
    base = nfat + ndir + nminifat_secs          # first data sector
    total = base + ndata

    fat = [FREESECT] * (nfat * per)
    for i in range(nfat):
        fat[i] = FATSECT

    def link(secs):
        for k, s in enumerate(secs):
            fat[s] = secs[k + 1] if k + 1 < len(secs) else ENDOFCHAIN

    dir_secs = list(range(nfat, nfat + ndir))
    link(dir_secs)
    minifat_secs = list(range(nfat + ndir, nfat + ndir + nminifat_secs))
    link(minifat_secs)

    sectors = [bytearray(ss) for _ in range(total)]
    big_starts = []
    for (name, d), units in zip(big, alloc[:len(big)]):
        secs = [base + u for u in units]
        link(secs)
        big_starts.append(secs[0])
        for k, s in enumerate(secs):
            sectors[s][:] = d[k * ss:(k + 1) * ss].ljust(ss, b"\x00")
    root_start = ENDOFCHAIN
    if ministream:
        secs = [base + u for u in alloc[-1]]
        link(secs)
        root_start = secs[0]
        for k, s in enumerate(secs):
            sectors[s][:] = bytes(ministream[k * ss:(k + 1) * ss]).ljust(ss, b"\x00")

    for i in range(nfat):
        sectors[i][:] = struct.pack("<%dI" % per, *fat[i * per:(i + 1) * per])
    mf = struct.pack("<%dI" % len(minifat), *minifat).ljust(nminifat_secs * ss, b"\xff")
    for k, s in enumerate(minifat_secs):
        sectors[s][:] = mf[k * ss:(k + 1) * ss]

    # Directory: root, then streams as a right-sibling chain sorted by (length, upper-case name).
    def dentry(name, typ, start, size, left=NOSTREAM, right=NOSTREAM, child=NOSTREAM):
        raw = name.encode("utf-16-le") + b"\x00\x00"
        e = bytearray(128)
        e[:len(raw)] = raw
        struct.pack_into("<HBB3I", e, 0x40, len(raw) if name else 0, typ, 1, left, right, child)
        struct.pack_into("<IQ", e, 0x74, start, size)
        return bytes(e)

    order = sorted(range(len(streams)), key=lambda i: (len(streams[i][0]), streams[i][0].upper()))
    starts = {}
    bi = si = 0
    for i, (name, d) in enumerate(streams):
        if len(d) >= cutoff:
            starts[i] = big_starts[bi]
            bi += 1
        else:
            starts[i] = mini_alloc[si][0] if mini_alloc[si] else ENDOFCHAIN
            si += 1
    blob = dentry("Root Entry", 5, root_start, len(ministream), child=1 + order[0] if streams else NOSTREAM)
    right_of = {order[k]: (1 + order[k + 1]) for k in range(len(order) - 1)}
    for i, (name, d) in enumerate(streams):
        blob += dentry(name, 2, starts[i], len(d), right=right_of.get(i, NOSTREAM))
    blob = blob.ljust(ndir * ss, b"\x00")
    for k in range(entries, ndir * (ss // 128)):       # unused entries: siblings/child = NOSTREAM
        off = k * 128
        blob = blob[:off] + dentry("", 0, 0, 0) + blob[off + 128:]
    for k, s in enumerate(dir_secs):
        sectors[s][:] = blob[k * ss:(k + 1) * ss]

    hdr = bytearray(512)
    hdr[:8] = MAGIC
    struct.pack_into("<HHHHH", hdr, 0x18, 0x3E, version, 0xFFFE, 9 if version == 3 else 12, 6)
    struct.pack_into("<I", hdr, 0x28, ndir if version == 4 else 0)
    struct.pack_into("<III", hdr, 0x2C, nfat, dir_secs[0], 0)
    struct.pack_into("<IIIII", hdr, 0x38, cutoff, minifat_secs[0] if minifat_secs else ENDOFCHAIN,
                     nminifat_secs, ENDOFCHAIN, 0)
    difat = list(range(nfat)) + [FREESECT] * (109 - nfat)
    struct.pack_into("<109I", hdr, 0x4C, *difat)
    head = bytes(hdr).ljust(ss, b"\x00")
    return head + b"".join(bytes(s) for s in sectors)
