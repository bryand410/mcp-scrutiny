"""Generate the GitHub social preview card (1280x640).

One-off asset generation, not part of the package. Kept in the repository so the
card can be regenerated when the tagline changes, rather than being a mystery
binary nobody can edit.

    pip install pillow
    python scripts/make_social_preview.py
"""

from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = (11, 18, 32)
PANEL = (17, 27, 46)
INK = (237, 242, 250)
MUTED = (138, 155, 181)
ACCENT = (90, 160, 245)
CRIT = (232, 90, 90)
PILL_BG = (23, 36, 60)
PILL_EDGE = (44, 64, 98)

FONT_DIR = pathlib.Path("C:/Windows/Fonts")
OUT = pathlib.Path(__file__).resolve().parent.parent / "docs" / "social-preview.png"

DETECTORS = [
    ("pinning", "supply chain"),
    ("drift", "rug pulls"),
    ("semantic", "tool poisoning"),
    ("shadowing", "cross-server"),
    ("toxic flow", "composition"),
]


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    path = FONT_DIR / name
    if path.exists():
        return ImageFont.truetype(str(path), size)
    return ImageFont.load_default(size)


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    f_name = font("consolab.ttf", 62)
    f_prompt = font("consola.ttf", 34)
    f_tag_b = font("segoeuib.ttf", 28)
    f_pill = font("segoeuib.ttf", 20)
    f_pill_sub = font("segoeui.ttf", 17)
    f_foot = font("segoeui.ttf", 21)
    f_mono_sm = font("consola.ttf", 19)

    # Left accent bar
    d.rectangle([0, 0, 8, H], fill=ACCENT)

    # Header: a shell prompt, so the tool reads as a CLI at a glance
    x, y = 76, 78
    d.text((x, y), "$", font=f_prompt, fill=ACCENT)
    d.text((x + 34, y), "mcp-scrutiny scan --config mcp.json", font=f_prompt, fill=MUTED)

    # Project name
    d.text((x, y + 74), "mcp-scrutiny", font=f_name, fill=INK)

    # Tagline, two lines
    d.text((x, y + 176), "Static and semantic security scanner", font=f_tag_b, fill=INK)
    d.text((x, y + 214), "for Model Context Protocol servers.", font=f_tag_b, fill=INK)

    # Detector pills, two rows of three and two
    pill_y = 372
    px = x
    for i, (name, sub) in enumerate(DETECTORS):
        if i == 3:
            px = x
            pill_y += 76
        pw = 372
        d.rounded_rectangle([px, pill_y, px + pw, pill_y + 60], radius=10,
                            fill=PILL_BG, outline=PILL_EDGE, width=2)
        d.text((px + 20, pill_y + 10), name, font=f_pill, fill=INK)
        d.text((px + 20, pill_y + 34), sub, font=f_pill_sub, fill=MUTED)
        px += pw + 24

    # Footer
    d.line([76, 556, 1204, 556], fill=PILL_EDGE, width=2)
    d.text((76, 578), "zero dependencies", font=f_mono_sm, fill=ACCENT)
    d.text((300, 578), "|", font=f_mono_sm, fill=PILL_EDGE)
    d.text((324, 578), "fully offline", font=f_mono_sm, fill=ACCENT)
    d.text((510, 578), "|", font=f_mono_sm, fill=PILL_EDGE)
    d.text((534, 578), "SARIF for CI", font=f_mono_sm, fill=ACCENT)

    url = "github.com/bryand410/mcp-scrutiny"
    w_url = d.textlength(url, font=f_foot)
    d.text((1204 - w_url, 576), url, font=f_foot, fill=MUTED)

    # A single severity marker, so the card says what it is for
    d.rounded_rectangle([1040, 96, 1204, 148], radius=8, fill=(46, 20, 24), outline=CRIT, width=2)
    d.text((1062, 110), "CRITICAL", font=f_pill, fill=CRIT)

    img.save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT} ({OUT.stat().st_size / 1024:.0f} KB, {W}x{H})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
