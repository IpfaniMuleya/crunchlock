"""Draw the Crunchlock padlock icon (needs Pillow). Writes .ico and .png files."""
import sys
from pathlib import Path

from PIL import Image, ImageDraw


def draw(size: int = 256) -> Image.Image:
    s = size / 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    accent, dark = (43, 111, 214, 255), (29, 79, 156, 255)
    # shackle
    d.arc([14 * s, 9 * s, 50 * s, 45 * s], start=180, end=360, fill=dark, width=int(6 * s))
    d.rectangle([14 * s, 26 * s, 20 * s, 33 * s], fill=dark)
    d.rectangle([44 * s, 26 * s, 50 * s, 33 * s], fill=dark)
    # body
    d.rounded_rectangle([9 * s, 30 * s, 55 * s, 59 * s], radius=7 * s, fill=accent)
    # keyhole
    d.ellipse([28 * s, 38 * s, 36 * s, 46 * s], fill="white")
    d.rectangle([30.5 * s, 43 * s, 33.5 * s, 51 * s], fill="white")
    return img


def main(out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    img = draw(256)
    img.save(out / "crunchlock.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    img.save(out / "crunchlock.png")
    print(f"icons written to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "build/icons")
