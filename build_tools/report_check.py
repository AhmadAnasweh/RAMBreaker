"""Headless check of a RAMBreaker report.html (Playwright + Chromium).

For every report tab: screenshot + programmatic checks
  - JS console errors / page errors / failed requests (fonts, CSS)
  - empty tab (only 'empty' placeholders, no table rows)
  - tables: row count, all-empty columns (missing data cells)
  - horizontal page overflow (document wider than viewport)
  - clipped text in headers/stat tiles (scrollWidth > clientWidth)
  - overlapping stat tiles / cards
Usage: python report_check.py <report.html> <out_dir>
"""

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

JS_CHECK = r"""
() => {
  const page = document.querySelector('.page.active');
  const res = {tables: [], empty_markers: 0, clipped: [], overlaps: 0, text_len: 0};
  if (!page) return res;
  res.text_len = page.innerText.trim().length;
  res.empty_markers = page.querySelectorAll('.empty').length;
  page.querySelectorAll('table').forEach((t, ti) => {
    const rows = t.querySelectorAll('tbody tr');
    const heads = [...t.querySelectorAll('thead th')].map(h => h.innerText.trim());
    const emptyCols = [];
    if (rows.length) {
      heads.forEach((h, ci) => {
        let filled = 0;
        rows.forEach(r => { const c = r.children[ci]; if (c && c.innerText.trim()) filled++; });
        if (!filled) emptyCols.push(h);
      });
    }
    const w = t.closest('.tablewrap') || t.parentElement;
    res.tables.push({id: t.id || ('t' + ti), rows: rows.length, cols: heads.length,
                     empty_cols: emptyCols,
                     wrap_scrolls: w ? w.scrollWidth > w.clientWidth + 2 : false});
  });
  page.querySelectorAll('h1,h2,h3,.stat .n,.stat .l,.tab,th').forEach(e => {
    const cs = getComputedStyle(e);
    if (e.scrollWidth > e.clientWidth + 2 && cs.overflow !== 'visible' && e.clientWidth > 0)
      res.clipped.push((e.innerText || '').slice(0, 60));
  });
  const els = [...page.querySelectorAll('.stat,.card')].filter(e => {
    const r = e.getBoundingClientRect(); return r.width && r.height; });
  for (let i = 0; i < els.length; i++) for (let j = i + 1; j < els.length; j++) {
    if (els[i].contains(els[j]) || els[j].contains(els[i])) continue;  // nesting is not overlap
    const a = els[i].getBoundingClientRect(), b = els[j].getBoundingClientRect();
    const ox = Math.min(a.right, b.right) - Math.max(a.left, b.left);
    const oy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
    if (ox > 2 && oy > 2) res.overlaps++;
  }
  res.page_overflow_x = document.documentElement.scrollWidth > window.innerWidth + 2;
  return res;
}
"""


def main(report: Path, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    summary = {"report": str(report), "tabs": [], "console_errors": [], "failed_requests": []}
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1600, "height": 1000})
        pg.on("console", lambda m: m.type == "error" and summary["console_errors"].append(m.text[:300]))
        pg.on("pageerror", lambda e: summary["console_errors"].append(f"pageerror: {e}"[:300]))
        pg.on("requestfailed", lambda r: summary["failed_requests"].append(r.url[:200]))
        pg.goto(report.resolve().as_uri(), wait_until="load", timeout=120000)
        pg.wait_for_timeout(800)
        names = pg.eval_on_selector_all(".tab", "els => els.map(e => e.innerText.trim())")
        ids = pg.evaluate("() => PAGES.map(p => p[0])")
        for i, (tid, name) in enumerate(zip(ids, names)):
            pg.evaluate(f"() => showPage({json.dumps(tid)})")
            pg.wait_for_timeout(400)
            r = pg.evaluate(JS_CHECK)
            shot = out / f"report_{i:02d}_{tid}.png"
            pg.screenshot(path=str(shot))
            rows = sum(t["rows"] for t in r["tables"])
            r.update(tab=name, id=tid, screenshot=shot.name,
                     empty_tab=(rows == 0 and r["text_len"] < 400) or
                               (r["empty_markers"] > 0 and rows == 0))
            summary["tabs"].append(r)
        b.close()
    issues = []
    for t in summary["tabs"]:
        if t["empty_tab"]:
            issues.append(f"EMPTY tab: {t['tab']}")
        for tb in t["tables"]:
            if tb["empty_cols"]:
                issues.append(f"{t['tab']}/{tb['id']}: all-empty columns {tb['empty_cols'][:6]}")
        if t["clipped"]:
            issues.append(f"{t['tab']}: clipped text {t['clipped'][:3]}")
        if t["overlaps"]:
            issues.append(f"{t['tab']}: {t['overlaps']} overlapping boxes")
        if t.get("page_overflow_x"):
            issues.append(f"{t['tab']}: horizontal page overflow")
    if summary["console_errors"]:
        issues.append(f"console errors: {summary['console_errors'][:3]}")
    if summary["failed_requests"]:
        issues.append(f"failed requests: {summary['failed_requests'][:3]}")
    summary["issues"] = issues
    (out / "report_check.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"tabs={len(summary['tabs'])} issues={len(issues)}")
    for s in issues:
        print("  -", s)
    for t in summary["tabs"]:
        print(f"  [{t['id']}] tables={len(t['tables'])} rows={sum(x['rows'] for x in t['tables'])}"
              f" empty={t['empty_tab']}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
