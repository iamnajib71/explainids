"""Build the full submission for a group assessment: filled ECA cover sheet + report.

Steps: build the report .docx from Markdown, fill the cover sheet, merge both into one
Word file with Word itself (cover sheet first), and export that file to PDF, so the .docx
and .pdf submissions are identical. Outputs go to reports/<A>/submission/.

Usage (run inside a PowerShell Start-Job with a timeout; Word automation can hang otherwise):
    python reports/tools/make_submission.py A1
"""
import json
import sys
from pathlib import Path

import pymupdf

sys.path.insert(0, str(Path(__file__).parent))
from build_docx import build, split_front_matter  # noqa: E402
from fill_cover_sheet import ROOT, fill  # noqa: E402
from render import merge_docx, render  # noqa: E402


def set_properties(path, cfg) -> None:
    """Replace the template's metadata (author 'Admin', empty title) with the team's."""
    from docx import Document

    course = json.loads((ROOT / "reports" / "course_details.json").read_text(encoding="utf-8"))
    doc = Document(str(path))
    cp = doc.core_properties
    if cfg.get("template") == "individual":
        cp.author = course["students"][cfg["student_index"]]["name"]
    else:
        cp.author = "; ".join(s["name"] for s in course["students"])
    cp.last_modified_by = cp.author
    cp.title = f"{cfg['assessment_number']}: {cfg['assessment_title']}"
    doc.save(str(path))


def main(assessment: str) -> None:
    folder = ROOT / "reports" / assessment
    cfg = json.loads((folder / "cover_sheet.json").read_text(encoding="utf-8"))
    out_dir = folder / "submission"
    out_dir.mkdir(exist_ok=True)
    stem = Path(cfg["report_markdown"]).stem

    report_docx = out_dir / f"{stem}.docx"
    build(str(folder / cfg["report_markdown"]), str(report_docx))
    cover_docx = fill(assessment)

    meta, _ = split_front_matter((folder / cfg["report_markdown"]).read_text(encoding="utf-8"))
    has_cover = meta.get("cover_page", "true") != "false"
    merged_docx = merge_docx(str(cover_docx), str(report_docx), str(out_dir / f"{stem}_SUBMISSION.docx"), has_cover)
    set_properties(merged_docx, cfg)
    rendered = render(str(merged_docx), str(out_dir / "_render"))
    final = out_dir / f"{stem}_SUBMISSION.pdf"
    final.write_bytes(Path(rendered).read_bytes())
    with pymupdf.open(final) as d:
        print(f"Submission PDF: {final} ({d.page_count} pages)")


if __name__ == "__main__":
    main(sys.argv[1])
