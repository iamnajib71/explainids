import struct

from scripts.resegment_pcap import FIN, PSH, ipv4_checksum, resegment, split_frame


def tcp_frame(payload_len: int, flags: int = PSH | 0x10, seq: int = 1000) -> bytes:
    eth = b"\x00" * 12 + b"\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", 51000, 443, seq, 0, 5 << 4, flags, 65535, 0, 0)
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 20 + payload_len, 7, 0x4000, 64, 6, 0,
                               bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])))
    struct.pack_into("!H", ip, 10, ipv4_checksum(bytes(ip)))
    return eth + bytes(ip) + tcp + bytes(range(256)) * (payload_len // 256) + bytes(payload_len % 256)


def test_small_segments_are_untouched():
    f = tcp_frame(1000)
    assert split_frame(f, 1460) == [f]


def test_super_packet_splits_with_contiguous_sequence_and_flags_on_last_piece():
    f = tcp_frame(4000, flags=PSH | FIN | 0x10, seq=5000)
    pieces = split_frame(f, 1460)
    assert [len(p) - 54 for p in pieces] == [1460, 1460, 1080]
    seqs = [struct.unpack_from("!I", p, 38)[0] for p in pieces]
    assert seqs == [5000, 6460, 7920]
    flags = [p[47] for p in pieces]
    assert all(not fl & (FIN | PSH) for fl in flags[:-1]) and flags[-1] & FIN and flags[-1] & PSH
    for p in pieces:
        assert struct.unpack_from("!H", p, 16)[0] == len(p) - 14          # IP total length
        assert ipv4_checksum(p[14:34]) == 0                                 # valid header checksum
    assert b"".join(p[54:] for p in pieces) == f[54:]                      # payload preserved in order


def test_pcap_roundtrip_counts_and_timestamps(tmp_path):
    src, dst = tmp_path / "in.pcap", tmp_path / "out.pcap"
    frames = [tcp_frame(3000), tcp_frame(100)]
    with src.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            fh.write(struct.pack("<IIII", 100 + i, 999_999, len(fr), len(fr)) + fr)
    stats = resegment(src, dst)
    assert stats == {"packets_in": 2, "packets_out": 4, "split": 1, "truncated_skipped": 0}
    data = dst.read_bytes()[24:]
    stamps, pos = [], 0
    while pos < len(data):
        sec, usec, cap, _ = struct.unpack_from("<IIII", data, pos)
        stamps.append((sec, usec))
        pos += 16 + cap
    assert stamps == [(100, 999_999), (101, 0), (101, 1), (101, 999_999)]
