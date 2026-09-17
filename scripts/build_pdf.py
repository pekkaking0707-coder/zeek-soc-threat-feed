"""Build the Zeek SOC Threat Feed PDFs from markdown sources.

Pipeline: markdown -> styled HTML -> headless Edge print-to-pdf.
Run from repo root:  python scripts/build_pdf.py

Jobs:
  Zeek_SOC_Build_Plan.pdf  <- PLAN.md + BUILD_GUIDE.md
  Zeek_SOC_Explainer.pdf   <- EXPLAINER.md
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

JOBS = [
    ("Zeek_SOC_Build_Plan.pdf", [ROOT / "PLAN.md", ROOT / "BUILD_GUIDE.md"]),
    ("Zeek_SOC_Explainer.pdf", [ROOT / "EXPLAINER.md"]),
]

CSS = """
body { font-family: 'Segoe UI', Calibri, sans-serif; font-size: 10.5pt; color: #1a1a1a;
       max-width: 780px; margin: 0 auto; padding: 24px 8px; }
h1 { font-size: 17pt; border-bottom: 2px solid #24292f; padding-bottom: 6px; margin-top: 28px; }
h2 { font-size: 13.5pt; border-bottom: 1px solid #c9c9c9; padding-bottom: 3px; margin-top: 22px; }
h3 { font-size: 11.5pt; margin-top: 16px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 9pt; }
th, td { border: 1px solid #999; padding: 4px 6px; text-align: left; vertical-align: top; }
th { background: #eef1f4; }
pre { background: #f5f7f9; border: 1px solid #ddd; padding: 8px; font-size: 8pt;
      white-space: pre-wrap; word-wrap: break-word; }
code { font-family: Consolas, monospace; background: #f0f0f0; padding: 0 3px; font-size: 90%; }
pre code { background: none; padding: 0; }
blockquote { border-left: 4px solid #888; margin: 8px 0; padding: 4px 12px; color: #333; background:#fafafa; }
.title-page { text-align: center; margin: 220px 0 60px; }
.title-page h1 { border: none; font-size: 22pt; }
@page { size: A4; margin: 18mm 14mm; }
"""


def ensure_markdown() -> None:
    if importlib.util.find_spec("markdown") is None:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "markdown"])


def find_edge() -> pathlib.Path:
    candidates = [
        pathlib.Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        pathlib.Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("msedge.exe not found - install Edge or adapt this script")


def render(out_pdf: pathlib.Path, sources: list[pathlib.Path], title: str, subtitle: str) -> None:
    import markdown

    body = []
    for src in sources:
        text = src.read_text(encoding="utf-8")
        html = markdown.markdown(text, extensions=["tables", "fenced_code"])
        body.append(f'<div class="chapter">{html}<div style="page-break-after: always"></div></div>')

    title_page = (
        f'<div class="title-page"><h1>{title}</h1>'
        f'<p><b>{subtitle}</b></p>'
        '<p>Zeek SOC Threat Feed & Analytics Dashboard</p>'
        '<p>Open-Source Network Security Monitoring</p></div>'
        '<div style="page-break-after: always"></div>'
    )

    html_doc = f"<!DOCTYPE html><html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{title_page}{''.join(body)}</body></html>"

    with tempfile.TemporaryDirectory() as td:
        tmp_html = pathlib.Path(td) / "doc.html"
        tmp_html.write_text(html_doc, encoding="utf-8")
        edge = find_edge()
        subprocess.run([
            str(edge), "--headless", "--disable-gpu",
            f"--print-to-pdf={out_pdf}",
            "--no-pdf-header-footer",
            tmp_html.as_uri(),
        ], check=True, capture_output=True, timeout=120)

    size = out_pdf.stat().st_size
    print(f"OK: {out_pdf.name} ({size / 1024:.0f} KB)")
    if size < 10_000:
        raise SystemExit(f"{out_pdf.name} suspiciously small - inspect HTML rendering")


def main() -> None:
    ensure_markdown()
    render(ROOT / "Zeek_SOC_Build_Plan.pdf", JOBS[0][1],
           "Zeek SOC Threat Feed & Analytics Dashboard<br>Architecture & Build Guide",
           "Streaming Threat Detection for Unidirectional Mirrored Traffic")
    render(ROOT / "Zeek_SOC_Explainer.pdf", JOBS[1][1],
           "Zeek SOC Threat Feed & Analytics Dashboard",
           "Concepts · Architecture · Tools · Data Flow · Results")


if __name__ == "__main__":
    main()