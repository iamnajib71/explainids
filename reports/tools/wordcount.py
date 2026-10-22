"""Word count for report drafts.

Counts body prose separately from tables, figure captions and references,
so the total can be checked against the brief's word limit either way.

Usage: python reports/tools/wordcount.py reports/A1/A1_Project_Brief.md
"""
import re
import sys
from pathlib import Path

CAPTION_LABEL = re.compile(r"\*\*(Table|Figure) [A-Z]?\d+\*\*")


def words(text: str) -> int:
    text = re.sub(r"\[\[.*?\]\]", "", text)          # placeholders
    text = re.sub(r"!\[.*?\]\(.*?\)(\{.*?\})?", "", text)  # images
    text = re.sub(r"[*_#>`|]", " ", text)            # markdown symbols
    return len([w for w in text.split() if re.search(r"\w", w)])


def count(path: str) -> dict:
    raw = Path(path).read_text(encoding="utf-8")
    raw = re.sub(r"^---\n.*?\n---\n", "", raw, flags=re.S)  # front matter (cover page)
    body, _, refs = raw.partition("\n# References")
    refs = refs.split("\n# Appendix")[0]  # appendices are not counted

    prose, tables, captions = [], [], []
    lines = body.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("|"):
            if not re.fullmatch(r"\|[\s\-:|]+\|", s):
                tables.append(s)
        elif CAPTION_LABEL.fullmatch(s) or (i > 0 and CAPTION_LABEL.fullmatch(lines[i - 1].strip())):
            captions.append(s)
        else:
            prose.append(s)

    return {
        "prose": words("\n".join(prose)),
        "tables": words("\n".join(tables)),
        "captions": words("\n".join(captions)),
        "references": words(refs),
    }


def main(path: str) -> None:
    c = count(path)
    print(f"Body prose (incl. headings): {c['prose']}")
    print(f"Tables:                      {c['tables']}")
    print(f"Table/figure captions:       {c['captions']}")
    print(f"References:                  {c['references']}")
    print(f"Prose + tables:              {c['prose'] + c['tables']}")


if __name__ == "__main__":
    main(sys.argv[1])
