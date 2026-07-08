#!/usr/bin/env python3
"""
ascii_art.py, Clearfront ASCII-art generator for brand wordmarks, symbols, and lockups.

Produces themeable ASCII art (plain text → drop in a <pre>; CSS recolours it for
light/dark, so you generate once and it works in both themes). Three sources:

  • symbol  , procedural marks from pure math (orb, globe, radar, rings, waves)
  • wordmark, the brand name as a big ASCII banner (pyfiglet, 500+ fonts)
  • image   , convert any image file to ASCII (Pillow)
  • lockup  , a symbol stacked above a wordmark (the full brand lockup)

Examples
--------
  python scripts/ascii_art.py symbol orb --width 70
  python scripts/ascii_art.py symbol globe --width 60
  python scripts/ascii_art.py wordmark "CLEARFRONT" --font ansi_shadow
  python scripts/ascii_art.py lockup "CLEARFRONT" --symbol orb --width 64
  python scripts/ascii_art.py image logo.png --width 100
  python scripts/ascii_art.py wordmark "CLEARFRONT" --html   # ready to paste into index.html
  python scripts/ascii_art.py fonts                         # list good wordmark fonts

Notes
-----
* Character cells are ~2:1 (tall:wide); round symbols use rows = width // 2 so
  circles render round.
* For the web UI you do NOT invert, keep the characters and let CSS colour them.
  --invert is only for fixed-background media (e.g. printing on a white terminal).
"""
from __future__ import annotations

import argparse
import math
import sys

# Coarse ramp for clean geometric symbols. Index by intensity in [0, 1].
RAMP = " .:-=+*#%@"
# Fine 70-level ramp (Paul Bourke) for DETAILED image/render conversion, this
# density resolution is what makes converted art look rich rather than blocky.
DETAIL_RAMP = (
    " .'`^\",:;Il!i><~+_-?][}{1)(|\\/tfjrxnuvczXYUJCLQ0OZmwqpdbkhao*#MW&8%B@$"
)
# A curated set of wordmark fonts that read clean/institutional.
SUGGESTED_FONTS = [
    "standard", "ansi_regular", "ansi_shadow", "small", "slant",
    "banner3", "big", "doom", "graffiti", "isometric1", "block",
]


# ── helpers ───────────────────────────────────────────────────────────────────

def _dims(width: int) -> tuple[int, int]:
    """Return (cols, rows) with rows halved for the 2:1 character aspect ratio."""
    width = max(8, int(width))
    return width, max(4, round(width * 0.5))


def _shade(intensity: float, ramp: str = RAMP) -> str:
    intensity = 0.0 if intensity < 0 else 1.0 if intensity > 1 else intensity
    return ramp[min(len(ramp) - 1, int(intensity * (len(ramp) - 1)))]


def _norm(col: int, row: int, W: int, H: int) -> tuple[float, float]:
    """Cell → (x, y) in [-1, 1]."""
    x = (col / (W - 1)) * 2 - 1 if W > 1 else 0.0
    y = (row / (H - 1)) * 2 - 1 if H > 1 else 0.0
    return x, y


def _finish(lines: list[str], invert: bool, html: bool) -> str:
    if invert:
        lines = [_invert_line(ln) for ln in lines]
    text = "\n".join(ln.rstrip() for ln in lines).strip("\n")
    if html:
        text = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        return f'<pre class="ascii-art" aria-hidden="true">{text}</pre>'
    return text


def _invert_line(line: str) -> str:
    rev = RAMP[::-1]
    return "".join(rev[RAMP.index(c)] if c in RAMP else c for c in line)


# ── procedural symbols ────────────────────────────────────────────────────────

def orb(width: int) -> list[str]:
    """A shaded sphere lit from the upper-left, the 'intelligence globe' mark."""
    W, H = _dims(width)
    L = (-0.55, -0.75, 0.6)
    ln = math.sqrt(sum(c * c for c in L))
    L = tuple(c / ln for c in L)
    out = []
    for row in range(H):
        line = []
        for col in range(W):
            x, y = _norm(col, row, W, H)
            r2 = x * x + y * y
            if r2 <= 1.0:
                z = math.sqrt(1 - r2)
                d = max(0.0, x * L[0] + y * L[1] + z * L[2])
                line.append(_shade(0.12 + 0.88 * d ** 1.4))
            else:
                line.append(" ")
        out.append("".join(line))
    return out


def globe(width: int) -> list[str]:
    """A wireframe sphere with latitude/longitude graticule, a recon/world mark."""
    W, H = _dims(width)
    LAT, LON = 30.0, 30.0
    out = []
    for row in range(H):
        line = []
        for col in range(W):
            x, y = _norm(col, row, W, H)
            r2 = x * x + y * y
            if r2 > 1.0:
                line.append(" ")
                continue
            if r2 > 0.95:            # limb / outline
                line.append("#")
                continue
            z = math.sqrt(1 - r2)
            lat = math.degrees(math.asin(max(-1.0, min(1.0, y))))
            lon = math.degrees(math.atan2(x, z))
            dlat = lat % LAT
            dlat = min(dlat, LAT - dlat)
            dlon = lon % LON
            dlon = min(dlon, LON - dlon)
            if dlat < 3.0 or dlon < 4.5:
                line.append("+")
            else:
                line.append(" ")
        out.append("".join(line))
    return out


def radar(width: int) -> list[str]:
    """Concentric range rings + crosshair + sweep + blips, a sensor/scope mark."""
    W, H = _dims(width)
    rstep, sweep = 0.26, math.radians(-35)
    blips = [(0.42, -0.18), (-0.3, 0.36)]
    out = []
    for row in range(H):
        line = []
        for col in range(W):
            x, y = _norm(col, row, W, H)
            r = math.sqrt(x * x + y * y)
            ch = " "
            if r <= 1.0:
                ang = math.atan2(y, x)
                dr = r % rstep
                dr = min(dr, rstep - dr)
                if any(math.hypot(x - bx, y - by) < 0.05 for bx, by in blips):
                    ch = "@"
                elif r <= 1.0 and abs(((ang - sweep + math.pi) % (2 * math.pi)) - math.pi) < 0.05:
                    ch = "#"                       # sweep beam
                elif abs(x) < 0.015 or abs(y) < 0.03:
                    ch = ":"                       # crosshair
                elif r > 0.97 or dr < 0.022:
                    ch = "."                       # range rings / outline
            line.append(ch)
        out.append("".join(line))
    return out


def rings(width: int) -> list[str]:
    """A nucleus with tilted orbital ellipses, a systems/orbit mark."""
    W, H = _dims(width)
    orbits = [(0.95, 0.34), (0.7, 0.62), (0.45, 0.9)]
    out = []
    for row in range(H):
        line = []
        for col in range(W):
            x, y = _norm(col, row, W, H)
            ch = " "
            if math.hypot(x, y) < 0.08:
                ch = "@"                           # nucleus
            else:
                for a, b in orbits:
                    v = (x / a) ** 2 + (y / b) ** 2
                    if abs(v - 1.0) < 0.06:
                        ch = "."
                        break
            line.append(ch)
        out.append("".join(line))
    return out


def waves(width: int) -> list[str]:
    """Stacked signal bands, a signals/telemetry mark."""
    W, H = _dims(width)
    out = []
    for row in range(H):
        line = []
        yc = (row / (H - 1)) * 2 - 1
        for col in range(W):
            t = col / (W - 1)
            amp = 0.18 * (1 - abs(yc))
            wave = amp * math.sin(t * math.pi * 6 + yc * 3)
            band = (row % 4 == 0)
            line.append("=" if band and abs(wave - 0) < 0.02 else ("·" if band else " "))
        out.append("".join(line))
    return out


# ── wordmark / image ──────────────────────────────────────────────────────────

def wordmark(text: str, font: str = "standard") -> list[str]:
    try:
        from pyfiglet import Figlet
    except ImportError:
        return _boxed(text)
    # width=400 stops long names wrapping to a second block in wide fonts.
    try:
        fig = Figlet(font=font, width=400)
    except Exception:
        fig = Figlet(width=400)
    rendered = fig.renderText(text)
    lines = [ln.rstrip() for ln in rendered.split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def _boxed(text: str) -> list[str]:
    """Zero-dependency fallback wordmark: a framed institutional label."""
    inner = f"  {text.upper()}  "
    bar = "─" * len(inner)
    return [f"┌{bar}┐", f"│{inner}│", f"└{bar}┘"]


def _img_to_ascii(img, width: int, ramp: str = DETAIL_RAMP) -> list[str]:
    """Convert a PIL grayscale image to ASCII at `width` columns with `ramp`."""
    img = img.convert("L")
    w, h = img.size
    new_h = max(1, int(width * (h / w) * 0.5))     # 0.5 for char aspect ratio
    img = img.resize((width, new_h))
    px = img.tobytes()                              # row-major 0–255 bytes (L mode)
    n = len(ramp) - 1
    out = []
    for row in range(new_h):
        out.append("".join(
            ramp[min(n, int((px[row * width + col] / 255) * n))] for col in range(width)
        ))
    return out


def image_to_ascii(path: str, width: int) -> list[str]:
    try:
        from PIL import Image
    except ImportError:
        sys.exit("Pillow required for image conversion: pip install pillow")
    return _img_to_ascii(Image.open(path), width)


def _fbm(px: int, octaves: int = 6, seed: int = 7):
    """Fractal Brownian-motion noise (0..1), built by summing upsampled octaves."""
    import numpy as np
    from PIL import Image
    rng = np.random.default_rng(seed)
    acc = np.zeros((px, px), dtype=float)
    amp, norm, cells = 1.0, 0.0, 3
    for _ in range(octaves):
        grid = (rng.random((cells, cells)) * 255).astype("uint8")
        up = np.asarray(Image.fromarray(grid).resize((px, px), Image.BICUBIC), dtype=float) / 255
        acc += amp * up
        norm += amp
        amp *= 0.5
        cells *= 2
    return acc / norm


def planet(width: int) -> list[str]:
    """A DETAILED shaded sphere: fractal-noise surface + diffuse lighting + limb
    darkening + atmospheric rim glow, rendered high-res then converted with the
    fine ramp. This is the 'rich' look (vs the clean `orb`)."""
    import numpy as np
    from PIL import Image
    px = max(360, width * 6)
    yy, xx = np.mgrid[0:px, 0:px]
    x = (xx / (px - 1)) * 2 - 1
    y = (yy / (px - 1)) * 2 - 1
    r2 = x * x + y * y
    mask = r2 <= 1.0
    z = np.sqrt(np.clip(1 - r2, 0, 1))
    L = np.array([-0.5, -0.7, 0.55]); L = L / np.linalg.norm(L)
    diffuse = np.clip(x * L[0] + y * L[1] + z * L[2], 0, 1)
    albedo = 0.45 + 0.55 * _fbm(px)            # surface "continents/clouds"
    limb = np.clip(z * 1.25, 0, 1)             # darken toward the edge
    inten = (0.08 + 0.92 * diffuse ** 1.3) * albedo * (0.45 + 0.55 * limb)
    rim = np.exp(-((1 - np.sqrt(np.clip(r2, 0, 4))) * 16) ** 2) * np.clip(diffuse + 0.25, 0, 1)
    inten = np.clip(inten + 0.45 * rim, 0, 1)  # atmospheric glow
    inten[~mask] = 0
    img = Image.fromarray((inten * 255).astype("uint8"), "L")
    return _img_to_ascii(img, width, DETAIL_RAMP)


SYMBOLS = {
    "planet": planet,   # DETAILED (numpy/PIL render → fine ramp)
    "orb": orb, "globe": globe, "radar": radar, "rings": rings, "waves": waves,
}


# Solid block glyphs → (y-offset fraction, height fraction) within a cell.
_BLOCK_RECT = {"█": (0.0, 1.0), "▀": (0.0, 0.5), "▄": (0.5, 0.5),
               "▌": (0.0, 1.0), "▐": (0.0, 1.0)}
def svg(text: str, font: str = "ansi_regular", italic: bool = False,
        cell: tuple[int, int] = (10, 18)) -> str:
    """Render a wordmark as ANSI-Shadow-style SVG.

    Solid filled letters (from a block font) PLUS a thin OUTLINE drop-shadow
    offset to the bottom-right, the classic ANSI-Shadow 3D look. Crisp at any
    size and themeable (fill/stroke = currentColor → recolours dark/light).
    `italic` skews the whole mark forward.
    """
    import math
    lines = wordmark(text, font)                # solid block letters
    while lines and not lines[-1].strip():
        lines.pop()
    rows = len(lines) or 1
    cols = max((len(l) for l in lines), default=1)
    CW, CH = cell
    sdx, sdy = round(CW * 0.5), round(CH * 0.4)  # shadow offset, bottom-right
    sw = 1.5                                       # shadow outline thickness

    fills, strokes = [], []
    for r, row in enumerate(lines):
        for c, ch in enumerate(row):
            if ch == " ":
                continue
            yoff, hfrac = _BLOCK_RECT.get(ch, (0.0, 1.0))
            x0 = c * CW
            y0 = r * CH + yoff * CH
            hh = hfrac * CH
            fills.append(f'<rect x="{x0}" y="{y0:.1f}" width="{CW}" height="{hh:.1f}"/>')
            strokes.append(f'<rect x="{x0+sdx}" y="{y0+sdy:.1f}" width="{CW}" height="{hh:.1f}"/>')

    pad = int(rows * CH * math.tan(math.radians(12))) if italic else 0
    vw = cols * CW + sdx + pad
    vh = rows * CH + sdy
    shadow = f'<g fill="none" stroke="currentColor" stroke-width="{sw}">{"".join(strokes)}</g>'
    body = f'<g>{"".join(fills)}</g>'
    inner = shadow + body                          # shadow behind, fill on top
    transform = f'translate({pad},0) skewX(-12)' if italic else ""
    group = f'<g transform="{transform}">{inner}</g>' if transform else inner
    return (
        f'<svg viewBox="0 0 {vw} {vh}" xmlns="http://www.w3.org/2000/svg" '
        f'fill="currentColor" shape-rendering="crispEdges" '
        f'preserveAspectRatio="xMidYMid meet" role="img" aria-label="{text}">{group}</svg>'
    )


def lockup(text: str, symbol_kind: str, width: int, font: str = "small") -> list[str]:
    sym = SYMBOLS[symbol_kind](width)
    mark = [ln.rstrip() for ln in wordmark(text, font) if ln.strip()]
    block_w = max((len(ln) for ln in sym + mark), default=width)
    centred = [ln.center(block_w) for ln in sym] + [""] + [ln.center(block_w) for ln in mark]
    return centred


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Clearfront ASCII-art generator")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--width", type=int, default=70, help="character width (default 70)")
        sp.add_argument("--invert", action="store_true", help="invert ramp (for light backgrounds)")
        sp.add_argument("--html", action="store_true", help="wrap output in a themeable <pre>")

    sp = sub.add_parser("symbol", help="procedural symbol")
    sp.add_argument("kind", choices=sorted(SYMBOLS))
    common(sp)

    sp = sub.add_parser("wordmark", help="text → ASCII banner")
    sp.add_argument("text")
    sp.add_argument("--font", default="standard")
    common(sp)

    sp = sub.add_parser("lockup", help="symbol + wordmark")
    sp.add_argument("text")
    sp.add_argument("--symbol", default="orb", choices=sorted(SYMBOLS))
    sp.add_argument("--font", default="small")
    common(sp)

    sp = sub.add_parser("image", help="image file → ASCII")
    sp.add_argument("path")
    common(sp)

    sp = sub.add_parser("svg", help="ANSI-Shadow-style wordmark → crisp themeable SVG")
    sp.add_argument("text")
    sp.add_argument("--font", default="ansi_regular")
    sp.add_argument("--italic", action="store_true")

    sub.add_parser("fonts", help="list suggested wordmark fonts")

    args = p.parse_args(argv)

    if args.cmd == "fonts":
        print("Suggested fonts (use with `wordmark --font NAME`):")
        for f in SUGGESTED_FONTS:
            print(f"  {f}")
        print("\nFull list: python -c \"import pyfiglet; print('\\n'.join(pyfiglet.FigletFont.getFonts()))\"")
        return 0

    if args.cmd == "symbol":
        lines = SYMBOLS[args.kind](args.width)
    elif args.cmd == "wordmark":
        lines = wordmark(args.text, args.font)
    elif args.cmd == "lockup":
        lines = lockup(args.text, args.symbol, args.width, args.font)
    elif args.cmd == "image":
        lines = image_to_ascii(args.path, args.width)
    elif args.cmd == "svg":
        print(svg(args.text, args.font, italic=args.italic))
        return 0
    else:
        p.error("unknown command")

    print(_finish(lines, args.invert, args.html))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
