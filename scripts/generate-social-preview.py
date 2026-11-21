"""Render the project social card with Pillow; the PNG is committed for docs CI.

Run from the repository root: python scripts/generate-social-preview.py
Uses Segoe UI on Windows or DejaVu Sans on Linux. No native SDK is loaded.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SCALE = 2


def font(size, bold=False):
    name = 'segoeuib.ttf' if bold else 'segoeui.ttf'
    fallback = 'DejaVuSans-Bold.ttf' if bold else 'DejaVuSans.ttf'
    for path in (Path('C:/Windows/Fonts') / name,
                 Path('/usr/share/fonts/truetype/dejavu') / fallback):
        if path.is_file():
            return ImageFont.truetype(str(path), size * SCALE)
    raise RuntimeError('Install Segoe UI or DejaVu Sans to regenerate the social card')


def main():
    image = Image.new('RGB', (1200 * SCALE, 630 * SCALE))
    draw = ImageDraw.Draw(image)
    for x in range(image.width):
        mix = (x / image.width) ** 1.7
        color = tuple(round(a + (b - a) * mix) for a, b in zip((250, 251, 255), (224, 230, 252)))
        draw.line((x, 0, x, image.height), fill=color)

    def box(bounds, radius, fill, outline=None, width=1):
        draw.rounded_rectangle(tuple(int(v * SCALE) for v in bounds), radius=radius * SCALE,
                               fill=fill, outline=outline, width=width * SCALE)

    def text(x, y, value, size, color, bold=False):
        draw.text((x * SCALE, y * SCALE), value, font=font(size, bold), fill=color)

    indigo = '#3F51B5'
    ink = '#17213F'
    text(72, 62, 'OPEN-SOURCE CRYPTOGRAPHY', 18, indigo, True)
    text(68, 151, 'PQ-CP-ABE', 84, ink, True)
    text(72, 261, 'Post-Quantum Access Control SDK', 36, ink, True)
    text(72, 326, 'AC17  /  TKN20  /  CoverCrypt', 27, '#526080')

    # Same indigo tile and shield/check motif as docs/assets/icons/crypto-lock.svg.
    box((870, 160, 1128, 418), 64, indigo)
    shield = [(999, 207), (1028, 227), (1062, 237), (1062, 287),
              (1053, 320), (1031, 346), (999, 365), (967, 346),
              (945, 320), (936, 287), (936, 237), (970, 227), (999, 207)]
    draw.line([(x * SCALE, y * SCALE) for x, y in shield], fill='white', width=8 * SCALE, joint='curve')
    draw.line([(970 * SCALE, 284 * SCALE), (991 * SCALE, 305 * SCALE),
               (1030 * SCALE, 264 * SCALE)], fill='white', width=9 * SCALE, joint='curve')

    x = 72
    for label, width in [('C / C++', 140), ('Python', 134), ('JavaScript / WASM', 250)]:
        box((x, 425, x + width, 477), 13, '#FFFFFF', '#CFD7F0')
        text(x + 18, 435, label, 22, indigo, True)
        x += width + 14
    draw.line((72 * SCALE, 530 * SCALE, 1128 * SCALE, 530 * SCALE), fill='#D3DAEE', width=2)
    text(72, 557, 'wanthinnn.github.io/pq-cp-abe', 21, '#526080')
    text(887, 557, 'by WanThinnn', 21, '#526080')
    output = ROOT / 'docs/assets/og-preview.png'
    image.resize((1200, 630), Image.Resampling.LANCZOS).save(output, optimize=True)
    print(output)


if __name__ == '__main__':
    main()
