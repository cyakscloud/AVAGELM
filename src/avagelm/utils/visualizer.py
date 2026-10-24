"""Small dependency-free SVG and PNG summary charts."""
from __future__ import annotations

from pathlib import Path


def charts(summary: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    vals = [summary.get("baseline_unauthorized_tool_calls", 0), summary.get("defended_unauthorized_tool_calls", 0)]
    labels = ["Unprotected baseline", "Taint-gated"]
    maxval = max(vals + [1])
    width, height = 900, 480
    chunks = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
              '<rect width="100%" height="100%" fill="#f7f9fc"/>',
              '<text x="48" y="48" font-family="Arial" font-size="24" font-weight="bold" fill="#172b4d">Unauthorized synthetic tool execution</text>']
    for i, (label, value, color) in enumerate(zip(labels, vals, ["#d94b4b", "#167d6d"])):
        y = 120 + i * 145
        bar = int(630 * value / maxval) if value else 0
        chunks += [f'<text x="50" y="{y}" font-family="Arial" font-size="19" fill="#243b53">{label}</text>',
                   f'<rect x="50" y="{y+20}" width="{max(bar, 3)}" height="66" rx="8" fill="{color}"/>',
                   f'<text x="{min(700, 65+bar)}" y="{y+64}" font-family="Arial" font-size="23" font-weight="bold" fill="#172b4d">{value}</text>']
    chunks.append(f'<text x="50" y="440" font-family="Arial" font-size="14" fill="#52606d">Live model trials: {summary.get("live_trials", 0)}; failed calls excluded from success denominator.</text></svg>')
    svg = "\n".join(chunks)
    (out / "asr_comparison.svg").write_text(svg, encoding="utf-8")
    try:
        from PIL import Image, ImageDraw, ImageFont
        im = Image.new("RGB", (width, height), "#f7f9fc"); d = ImageDraw.Draw(im)
        title = ImageFont.truetype("arial.ttf", 25)
        font = ImageFont.truetype("arial.ttf", 18)
        d.text((48, 30), "Unauthorized synthetic tool execution", fill="#172b4d", font=title)
        for i, (label, value, color) in enumerate(zip(labels, vals, ["#d94b4b", "#167d6d"])):
            y = 120 + i*145; bar = int(630*value/maxval) if value else 3
            d.text((50, y), label, fill="#243b53", font=font); d.rounded_rectangle((50,y+30,50+bar,y+88), radius=6, fill=color)
            d.text((min(700,65+bar),y+44), str(value), fill="#172b4d", font=title)
        d.text((50, 440), f"Live model trials: {summary.get('live_trials',0)}; model errors excluded.", fill="#52606d", font=ImageFont.truetype("arial.ttf", 14))
        im.save(out / "asr_comparison.png")
    except Exception:
        pass
