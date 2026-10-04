"""The social preview card.

Whatever gets pasted into LinkedIn or Slack renders this, so it is drawn from
live counters rather than shipped as a static asset. A card that says 14,203
attempts is doing work a stock graphic cannot.

SVG rather than a raster, because it needs no imaging dependency. A PNG
fallback is produced only if cairosvg happens to be installed.
"""
from __future__ import annotations

import html
import time

W, H = 1200, 630


def _fmt(n: int) -> str:
    return f"{n:,}"


def _short(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 10_000:
        return f"{n // 1000}k"
    return f"{n:,}"


def build_svg(stats: dict, split: dict, top_countries: list, site: str, brand: str = "Uninvited") -> str:
    total = stats.get("total", 0)
    attacks = (split.get("hits") or {}).get("attack", 0)
    research = (split.get("hits") or {}).get("research", 0)
    hosts = sum((split.get("hosts") or {}).values())

    tiles = [
        (_short(total), "TOTAL ATTEMPTS"),
        (_short(attacks or total), "GENUINE ATTACKS"),
        (_short(hosts), "UNIQUE HOSTS"),
        (_short(research), "RESEARCH SCANS"),
    ]

    flags = ""
    for i, (name, count) in enumerate(top_countries[:4]):
        x = 78 + i * 268
        # Counts previously sat at y=584, exactly on the footer rule.
        flags += (
            f'<text x="{x}" y="522" fill="#c2c2ca" font-size="20">'
            f'{html.escape((name or "Unknown")[:18])}</text>'
            f'<text x="{x}" y="550" fill="#6b7280" font-size="17">{_fmt(count)}</text>'
        )

    tile_svg = ""
    for i, (value, label) in enumerate(tiles):
        x = 70 + i * 268
        accent = "#dc2626" if i < 2 else "#6b7280"
        tile_svg += f"""
    <g>
      <rect x="{x}" y="330" width="230" height="132" fill="rgba(255,255,255,0.03)"
            stroke="rgba(255,255,255,0.08)"/>
      <path d="M{x} {330 + 16} L{x} {330} L{x + 16} {330}" stroke="{accent}" fill="none" stroke-width="2"/>
      <path d="M{x + 230} {462 - 16} L{x + 230} {462} L{x + 230 - 16} {462}" stroke="{accent}" fill="none" stroke-width="2"/>
      <text x="{x + 22}" y="396" fill="#f4f4f5" font-size="52" font-weight="700">{value}</text>
      <text x="{x + 22}" y="430" fill="#9a9aa5" font-size="17" letter-spacing="2">{label}</text>
    </g>"""

    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}"
     font-family="JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace">
  <defs>
    <radialGradient id="wash" cx="50%" cy="-10%" r="80%">
      <stop offset="0%" stop-color="#dc2626" stop-opacity="0.22"/>
      <stop offset="45%" stop-color="#dc2626" stop-opacity="0.05"/>
      <stop offset="100%" stop-color="#08080a" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <rect width="{W}" height="{H}" fill="#08080a"/>
  <rect width="{W}" height="{H}" fill="url(#wash)"/>

  <rect x="0" y="0" width="{W}" height="42" fill="rgba(220,38,38,0.14)"/>
  <line x1="0" y1="42" x2="{W}" y2="42" stroke="rgba(220,38,38,0.35)"/>
  <text x="{W // 2}" y="28" fill="#fca5a5" font-size="16" letter-spacing="4"
        text-anchor="middle">{html.escape(brand.upper())} // A SERVER LEFT OPEN ON PURPOSE // UNSOLICITED TRAFFIC ONLY</text>

  <rect x="70" y="92" width="52" height="52" rx="10" fill="#dc2626"/>
  <rect x="98" y="92" width="6" height="52" fill="#08080a"/>

  <text x="70" y="215" fill="#f4f4f5" font-size="60" font-weight="700" letter-spacing="-1">
    THIS SERVER IS</text>
  <text x="70" y="283" font-size="60" font-weight="700" letter-spacing="-1">
    <tspan fill="#f4f4f5">LEFT </tspan><tspan fill="#ef4444">OPEN ON PURPOSE</tspan></text>
{tile_svg}

  <text x="70" y="494" fill="#6b7280" font-size="15" letter-spacing="3">TOP ORIGINS</text>
  {flags}

  <line x1="0" y1="{H - 46}" x2="{W}" y2="{H - 46}" stroke="rgba(220,38,38,0.3)"/>
  <text x="70" y="{H - 18}" fill="#9a9aa5" font-size="16">{html.escape(site)}</text>
  <text x="{W - 70}" y="{H - 18}" fill="#6b7280" font-size="15" text-anchor="end">{stamp}</text>
</svg>"""


def _font(paths: list[str], size: int):
    from PIL import ImageFont
    for path in paths:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            continue
    from PIL import ImageFont as IF
    return IF.load_default()


# The Linux paths are the ones the server has. The Windows ones only matter when the card is
# looked at on a development machine; without them Pillow falls back to a tiny bitmap font.
MONO_FACES = [
    "/usr/share/fonts/truetype/jetbrains/JetBrainsMono-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
    "C:/Windows/Fonts/consolab.ttf",
]
SANS_FACES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "C:/Windows/Fonts/arial.ttf",
]
SANS_BOLD = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    "C:/Windows/Fonts/arialbd.ttf",
]


def build_png_native(stats: dict, split: dict, top_countries: list, site: str,
                     bars: list | None = None, brand: str = "Uninvited") -> bytes | None:
    """Draw the card directly with Pillow.

    Preferred over rasterising the SVG because cairosvg needs libcairo on the
    host, and a honeypot should not grow native dependencies for the sake of a
    preview image. Pillow ships wheels and the fonts are already there.
    """
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return None

    total = stats.get("total", 0)
    hits = split.get("hits") or {}
    hosts = sum((split.get("hosts") or {}).values())
    attacks = hits.get("attack", 0) or total
    research = hits.get("research", 0)

    BG, RED, RED_T = (11, 11, 12), (220, 38, 38), (239, 68, 68)
    TEXT, MUTED, DIM = (242, 242, 240), (154, 154, 159), (107, 107, 112)
    RULE = (38, 38, 42)

    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # The counter grows a digit every so often. Step the size down until it
    # stays clear of the divider at x=676 instead of running into it.
    hero_size = 118
    f_hero = _font(MONO_FACES, hero_size)
    while hero_size > 64 and 70 + d.textlength(f"{total:,}", font=f_hero) > 640:
        hero_size -= 4
        f_hero = _font(MONO_FACES, hero_size)
    f_head = _font(SANS_BOLD, 56)
    f_stat = _font(MONO_FACES, 40)
    f_lab = _font(SANS_FACES, 19)
    f_cap = _font(SANS_FACES, 18)
    f_small = _font(SANS_FACES, 17)
    f_strip = _font(SANS_FACES, 16)

    d.rectangle([0, 0, W, 44], fill=(30, 12, 13))
    d.line([(0, 44), (W, 44)], fill=(70, 22, 24))
    d.text((70, 15), f"{brand.upper()}   //   A SERVER LEFT OPEN ON PURPOSE   //   UNSOLICITED TRAFFIC ONLY",
           font=f_strip, fill=(252, 165, 165))

    # The mark from the site header: a red door with a sliver of dark down one
    # side, then the name.
    d.rectangle([70, 88, 90, 108], fill=RED)
    d.rectangle([82, 88, 84, 108], fill=BG)
    d.text((102, 88), brand.upper(), font=f_lab, fill=TEXT)

    d.text((70, 138), "THIS SERVER IS", font=f_head, fill=TEXT)
    x = 70
    for chunk, col in [("LEFT ", TEXT), ("OPEN ON PURPOSE", RED_T)]:
        d.text((x, 204), chunk, font=f_head, fill=col)
        x += d.textlength(chunk, font=f_head)

    # Hero number left, stats stacked right, so the width is actually used.
    d.text((70, 292), f"{total:,}", font=f_hero, fill=TEXT)
    d.text((76, 424), "UNSOLICITED CONNECTIONS CAPTURED", font=f_cap, fill=MUTED)

    col_x = 720
    d.line([(col_x - 44, 300), (col_x - 44, 452)], fill=RULE)
    for i, (value, label, col) in enumerate([
        (f"{attacks:,}", "genuine attacks", RED_T),
        (f"{research:,}", "research scans", TEXT),
        (f"{hosts:,}", "unique hosts", TEXT),
    ]):
        y = 300 + i * 54
        d.text((col_x, y), value, font=f_stat, fill=col)
        vw = d.textlength(value, font=f_stat)
        d.text((col_x + vw + 12, y + 15), label, font=f_lab, fill=MUTED)

    # 24h activity across the full width. Real data, and it fills the space
    # that a stat row alone left empty.
    if bars:
        peak = max(bars) or 1
        bx, by, bw_total, bh = 70, 528, W - 140, 42
        n = len(bars)
        step = bw_total / n
        for i, v in enumerate(bars):
            h = max(1, int(v / peak * bh))
            d.rectangle([bx + i * step, by + bh - h,
                         bx + i * step + max(1, step - 2), by + bh],
                        fill=RED if v == peak else (58, 58, 63))
        d.text((70, 500), "ACTIVITY / 24H", font=f_small, fill=DIM)
        if top_countries:
            line = "   ".join(f"{(n2 or 'Unknown')[:14]} {c:,}" for n2, c in top_countries[:3])
            lw = d.textlength(line, font=f_small)
            d.text((W - 70 - lw, 500), line, font=f_small, fill=DIM)
    elif top_countries:
        line = "   ".join(f"{(n2 or 'Unknown')[:16]} {c:,}" for n2, c in top_countries[:4])
        d.text((70, 545), line, font=f_small, fill=DIM)

    d.line([(0, H - 44), (W, H - 44)], fill=RULE)
    d.text((70, H - 32), site, font=f_small, fill=MUTED)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sw = d.textlength(stamp, font=f_small)
    d.text((W - 70 - sw, H - 32), stamp, font=f_small, fill=DIM)

    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def build_png(svg: str) -> bytes | None:
    """PNG only if the environment already has a renderer. Most platforms
    accept SVG for preview cards, and adding a native-code dependency to a
    honeypot for the sake of a social image is a bad trade."""
    try:
        import cairosvg  # type: ignore
        return cairosvg.svg2png(bytestring=svg.encode(), output_width=W,
                                output_height=H)
    except Exception:
        return None
