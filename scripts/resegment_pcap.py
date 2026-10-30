"""Undo segmentation offload in a capture: split oversized TCP segments into wire-sized packets.

  python scripts/resegment_pcap.py <in.pcap> <out.pcap> [--mss 1460]

A host captures its own traffic above the NIC, so with large-send / generic-receive offload it records
"super-packets" of up to 64 KB that never existed on the wire. Flow features (packet length statistics,
packet counts, inter-arrival times) then depend on where the sensor sits rather than on the traffic.
This rewrites each TCP segment whose payload exceeds the MSS into consecutive MSS-sized segments with
the same headers, advancing the sequence number, carrying FIN/PSH only on the last piece and keeping the
original timestamp plus `spacing_us` per piece (default 1 µs, which only preserves order; a
realistic value is the link's serialisation time, about 12 µs per full-size frame at 1 Gbit/s). IPv4 header checksums are recomputed; TCP
checksums are left stale, which the flow extractor does not read. Everything else is copied unchanged.

Supports classic pcap (micro- or nanosecond), Ethernet link type, optional 802.1Q tag, IPv4 and IPv6
without extension headers. It is a counterfactual tool for the observation-point experiment, not a
general packet rewriter.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

MAGIC = {0xA1B2C3D4: ("<", 1_000_000), 0xA1B23C4D: ("<", 1_000_000_000),
         0xD4C3B2A1: (">", 1_000_000), 0x4D3CB2A1: (">", 1_000_000_000)}
FIN, PSH = 0x01, 0x08


def ipv4_checksum(header: bytes) -> int:
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def split_frame(frame: bytes, mss: int) -> list[bytes]:
    """Return the frame unchanged, or the wire-sized TCP segments it stands for."""
    off = 12
    ethertype = struct.unpack_from("!H", frame, off)[0]
    if ethertype == 0x8100 and len(frame) >= 18:
        off += 4
        ethertype = struct.unpack_from("!H", frame, off)[0]
    l3 = off + 2
    if ethertype == 0x0800 and len(frame) >= l3 + 20:
        ihl = (frame[l3] & 0x0F) * 4
        if frame[l3 + 9] != 6 or struct.unpack_from("!H", frame, l3 + 6)[0] & 0x3FFF:
            return [frame]                                   # not TCP, or a fragment
        ip_len = struct.unpack_from("!H", frame, l3 + 2)[0] or len(frame) - l3   # LSO may leave 0
        l4, end = l3 + ihl, l3 + ip_len
    elif ethertype == 0x86DD and len(frame) >= l3 + 40:
        if frame[l3 + 6] != 6:
            return [frame]
        l4, end = l3 + 40, l3 + 40 + (struct.unpack_from("!H", frame, l3 + 4)[0] or len(frame) - l3 - 40)
    else:
        return [frame]
    if end > len(frame) or l4 + 20 > end:
        return [frame]
    thl = (frame[l4 + 12] >> 4) * 4
    payload = frame[l4 + thl:end]
    if len(payload) <= mss:
        return [frame]
    seq = struct.unpack_from("!I", frame, l4 + 4)[0]
    flags = frame[l4 + 13]
    head, tcp = frame[:l4], bytearray(frame[l4:l4 + thl])
    pieces = []
    for start in range(0, len(payload), mss):
        chunk = payload[start:start + mss]
        last = start + mss >= len(payload)
        t = bytearray(tcp)
        struct.pack_into("!I", t, 4, (seq + start) & 0xFFFFFFFF)
        t[13] = flags if last else flags & ~(FIN | PSH)
        h = bytearray(head)
        if ethertype == 0x0800:
            struct.pack_into("!H", h, l3 + 2, (l4 - l3) + thl + len(chunk))
            struct.pack_into("!H", h, l3 + 10, 0)
            struct.pack_into("!H", h, l3 + 10, ipv4_checksum(bytes(h[l3:l4])))
        else:
            struct.pack_into("!H", h, l3 + 4, thl + len(chunk))
        pieces.append(bytes(h) + bytes(t) + chunk)
    return pieces


def resegment(src: Path, dst: Path, mss: int = 1460, spacing_us: int = 1) -> dict:
    stats = {"packets_in": 0, "packets_out": 0, "split": 0, "truncated_skipped": 0}
    with src.open("rb") as fin, dst.open("wb") as fout:
        header = fin.read(24)
        magic = struct.unpack("<I", header[:4])[0]
        if magic not in MAGIC:
            raise ValueError("not a classic pcap file (pcapng is not supported)")
        endian, units = MAGIC[magic]
        if struct.unpack(endian + "I", header[20:24])[0] != 1:
            raise ValueError("only Ethernet captures are supported")
        fout.write(header)
        rec = struct.Struct(endian + "IIII")
        while chunk := fin.read(16):
            sec, frac, caplen, wirelen = rec.unpack(chunk)
            frame = fin.read(caplen)
            stats["packets_in"] += 1
            pieces = split_frame(frame, mss) if caplen == wirelen else [frame]
            if caplen != wirelen:
                stats["truncated_skipped"] += 1
            if len(pieces) > 1:
                stats["split"] += 1
            step = spacing_us * (units // 1_000_000)          # spacing in the file's units
            for i, p in enumerate(pieces):
                f = frac + i * step
                s, f = sec + f // units, f % units
                fout.write(rec.pack(s, f, len(p), len(p) if len(pieces) > 1 else wirelen) + p)
                stats["packets_out"] += 1
    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src", type=Path)
    ap.add_argument("dst", type=Path)
    ap.add_argument("--mss", type=int, default=1460)
    ap.add_argument("--spacing-us", type=int, default=1)
    args = ap.parse_args()
    print(resegment(args.src, args.dst, args.mss, args.spacing_us))


if __name__ == "__main__":
    main()
