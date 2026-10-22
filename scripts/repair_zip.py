"""Repair a partially corrupted download in place by re-fetching only the damaged members' byte ranges.

Usage: python scripts/repair_zip.py <zip> <url> <extract_dir>
Each member is CRC-checked while extracting; on failure its compressed byte range is downloaded
again with an HTTP Range request, patched into the file, and the member re-extracted.
"""
import sys
import urllib.request
import zipfile
from pathlib import Path

CHUNK = 8 * 1024 * 1024


def member_ranges(z: zipfile.ZipFile, size: int) -> dict[str, tuple[int, int]]:
    infos = sorted(z.infolist(), key=lambda i: i.header_offset)
    ends = [i.header_offset for i in infos[1:]] + [z.start_dir]
    return {i.filename: (i.header_offset, end) for i, end in zip(infos, ends)}


def patch(path: str, url: str, start: int, end: int) -> None:
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end - 1}"})
    with urllib.request.urlopen(req, timeout=120) as r, open(path, "r+b") as f:
        f.seek(start)
        done = 0
        while chunk := r.read(CHUNK):
            f.write(chunk)
            done += len(chunk)
            print(f"  patched {done / 1e6:,.0f} / {(end - start) / 1e6:,.0f} MB", end="\r", flush=True)
    print()


def main(path: str, url: str, out: str) -> None:
    out_dir = Path(out)
    for attempt in range(3):
        z = zipfile.ZipFile(path)
        ranges = member_ranges(z, Path(path).stat().st_size)
        bad = None
        for info in z.infolist():
            target = out_dir / info.filename
            if target.exists() and target.stat().st_size == info.file_size:
                continue
            try:
                z.extract(info, out_dir)
                print("ok", info.filename, flush=True)
            except (zipfile.BadZipFile, Exception) as exc:  # zlib.error or CRC mismatch
                print("damaged", info.filename, type(exc).__name__, flush=True)
                target.unlink(missing_ok=True)
                bad = info.filename
                break
        z.close()
        if bad is None:
            print("ALL_DONE")
            return
        patch(path, url, *ranges[bad])
    sys.exit("still damaged after 3 repair attempts")


if __name__ == "__main__":
    main(*sys.argv[1:4])
