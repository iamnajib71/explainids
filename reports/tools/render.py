"""Render a .docx to PDF with Microsoft Word, plus PNG page images for visual checks.

Usage: python reports/tools/render.py reports/A1/A1_Project_Brief_DRAFT.docx <out_dir> [dpi]
"""
import sys
from pathlib import Path

import pymupdf
import win32com.client

WD_FORMAT_PDF = 17
WD_FORMAT_DOCX = 16
WD_STATISTIC_PAGES = 2
WD_SECTION_BREAK_NEXT_PAGE = 2
WD_COLLAPSE_END = 0
WD_PAPER_A4 = 7
WD_HEADER_PRIMARY = 1
WD_FIELD_PAGE = 33
WD_ALIGN_RIGHT = 2


KEEP_STYLE_IDS = {"Normal", "DefaultParagraphFont", "TableNormal", "NoList"}


def isolate_styles(report: str, prefix: str = "Rpt") -> Path:
    """Copy the report with every non-default style renamed (e.g. BodyText -> RptBodyText).

    Word's InsertFile keeps the destination's definition when a style name exists in both
    documents, so the cover sheet's Body Text / Heading 1 would restyle the report.
    Unique names make the report bring its own definitions."""
    from docx import Document
    from docx.oxml.ns import qn

    doc = Document(report)
    styles = doc.styles.element
    mapping = {}
    for st in styles.iter(qn("w:style")):
        sid = st.get(qn("w:styleId"))
        if sid in KEEP_STYLE_IDS:
            continue
        mapping[sid] = prefix + sid
        st.set(qn("w:styleId"), prefix + sid)
        name = st.find(qn("w:name"))
        if name is not None:
            name.set(qn("w:val"), f"{prefix} {name.get(qn('w:val'))}")
    refs = ("w:basedOn", "w:next", "w:link", "w:pStyle", "w:rStyle", "w:tblStyle")
    parts = [styles, doc.element.body] + [s.header._element for s in doc.sections] + \
            [s.footer._element for s in doc.sections] + [s.first_page_header._element for s in doc.sections]
    for part in parts:
        for tag in refs:
            for el in part.iter(qn(tag)):
                val = el.get(qn("w:val"))
                if val in mapping:
                    el.set(qn("w:val"), mapping[val])
    out = Path(report).with_name(Path(report).stem + "_isolated.docx")
    doc.save(str(out))
    return out


def merge_docx(cover: str, report: str, out: str, report_has_cover: bool = True) -> Path:
    """Append the report after the cover sheet using Word itself, so images, styles and
    colours survive. The report gets its own A4 section with page numbers restarting at 1."""
    out_path = Path(out).resolve()
    report = str(isolate_styles(report))
    word = win32com.client.DispatchEx("Word.Application")
    word.DisplayAlerts = 0
    try:
        doc = word.Documents.Open(str(Path(cover).resolve()), False, False)
        rng = doc.Content
        rng.Collapse(WD_COLLAPSE_END)
        rng.InsertBreak(WD_SECTION_BREAK_NEXT_PAGE)
        rng = doc.Content
        rng.Collapse(WD_COLLAPSE_END)
        rng.InsertFile(str(Path(report).resolve()))

        sec = doc.Sections(doc.Sections.Count)
        ps = sec.PageSetup
        ps.PaperSize = WD_PAPER_A4
        ps.TopMargin = ps.BottomMargin = ps.LeftMargin = ps.RightMargin = 72  # 2.54 cm
        ps.DifferentFirstPageHeaderFooter = report_has_cover
        header = sec.Headers(WD_HEADER_PRIMARY)
        header.LinkToPrevious = False
        header.Range.Text = ""
        header.Range.Fields.Add(header.Range, WD_FIELD_PAGE)
        header.Range.ParagraphFormat.Alignment = WD_ALIGN_RIGHT
        first_header = sec.Headers(2)  # wdHeaderFooterFirstPage
        first_header.LinkToPrevious = False
        first_header.Range.Text = ""
        header.PageNumbers.RestartNumberingAtSection = True
        header.PageNumbers.StartingNumber = 1

        doc.SaveAs2(str(out_path), WD_FORMAT_DOCX)
        doc.Close(False)
    finally:
        word.Quit()
        Path(report).unlink(missing_ok=True)
    print(f"Merged Word file: {out_path}")
    return out_path


def render(docx: str, out_dir: str, dpi: int = 70) -> Path:
    src = Path(docx).resolve()
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    pdf = out / (src.stem + ".pdf")

    word = win32com.client.DispatchEx("Word.Application")
    word.DisplayAlerts = 0
    try:
        doc = word.Documents.Open(str(src), False, True)
        doc.SaveAs2(str(pdf), WD_FORMAT_PDF)
        pages = doc.ComputeStatistics(WD_STATISTIC_PAGES)
        doc.Close(False)
    finally:
        word.Quit()

    with pymupdf.open(pdf) as d:
        for i, page in enumerate(d, start=1):
            page.get_pixmap(dpi=dpi).save(out / f"page-{i:02d}.png")
    print(f"{pdf} ({pages} pages)")
    return pdf


if __name__ == "__main__":
    render(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 70)
