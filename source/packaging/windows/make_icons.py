from __future__ import annotations

import math
import struct
from pathlib import Path


OUT = Path(__file__).resolve().parent / "icons"
SIZES = (16, 32, 48, 64, 128)


def canvas(size: int) -> bytearray:
    return bytearray(size * size * 4)


def blend(img: bytearray, size: int, x: float, y: float, rgba: tuple[int, int, int, int]) -> None:
    x = round(x)
    y = round(y)
    if x < 0 or y < 0 or x >= size or y >= size:
        return
    r, g, b, a = rgba
    i = (y * size + x) * 4
    sa = a / 255
    da = img[i + 3] / 255
    oa = sa + da * (1 - sa)
    if oa <= 0:
        return
    img[i] = round((r * sa + img[i] * da * (1 - sa)) / oa)
    img[i + 1] = round((g * sa + img[i + 1] * da * (1 - sa)) / oa)
    img[i + 2] = round((b * sa + img[i + 2] * da * (1 - sa)) / oa)
    img[i + 3] = round(oa * 255)


def rect(img: bytearray, size: int, x0: float, y0: float, x1: float, y1: float, color) -> None:
    for y in range(math.floor(y0), math.ceil(y1) + 1):
        for x in range(math.floor(x0), math.ceil(x1) + 1):
            blend(img, size, x, y, color)


def circle(img: bytearray, size: int, cx: float, cy: float, r: float, color) -> None:
    rr = r * r
    for y in range(math.floor(cy - r), math.ceil(cy + r) + 1):
        for x in range(math.floor(cx - r), math.ceil(cx + r) + 1):
            dx = x + 0.5 - cx
            dy = y + 0.5 - cy
            if dx * dx + dy * dy <= rr:
                blend(img, size, x, y, color)


def round_rect(img: bytearray, size: int, x0: float, y0: float, x1: float, y1: float, r: float, color) -> None:
    rect(img, size, x0 + r, y0, x1 - r, y1, color)
    rect(img, size, x0, y0 + r, x1, y1 - r, color)
    circle(img, size, x0 + r, y0 + r, r, color)
    circle(img, size, x1 - r, y0 + r, r, color)
    circle(img, size, x0 + r, y1 - r, r, color)
    circle(img, size, x1 - r, y1 - r, r, color)


def inside_poly(x: float, y: float, pts: list[tuple[float, float]]) -> bool:
    inside = False
    j = len(pts) - 1
    for i, (xi, yi) in enumerate(pts):
        xj, yj = pts[j]
        if (yi > y) != (yj > y):
            at_x = (xj - xi) * (y - yi) / ((yj - yi) or 1e-9) + xi
            if x < at_x:
                inside = not inside
        j = i
    return inside


def polygon(img: bytearray, size: int, pts: list[tuple[float, float]], color) -> None:
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    for y in range(math.floor(min(ys)), math.ceil(max(ys)) + 1):
        for x in range(math.floor(min(xs)), math.ceil(max(xs)) + 1):
            if inside_poly(x + 0.5, y + 0.5, pts):
                blend(img, size, x, y, color)


def line(img: bytearray, size: int, x0: float, y0: float, x1: float, y1: float, width: float, color) -> None:
    steps = max(abs(x1 - x0), abs(y1 - y0), 1) * 2
    for i in range(round(steps) + 1):
        t = i / steps
        circle(img, size, x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, width / 2, color)


def shield_shape(n: int, pad: float = 0) -> list[tuple[float, float]]:
    return [
        (n * 0.50, n * (0.04 + pad)),
        (n * (0.86 - pad), n * (0.18 + pad)),
        (n * (0.82 - pad), n * (0.53 - pad)),
        (n * 0.68, n * 0.80),
        (n * 0.50, n * (0.94 - pad)),
        (n * 0.32, n * 0.80),
        (n * (0.18 + pad), n * (0.53 - pad)),
        (n * (0.14 + pad), n * (0.18 + pad)),
    ]


def draw_shield(img: bytearray, n: int) -> None:
    polygon(img, n, shield_shape(n), (245, 246, 248, 255))
    polygon(img, n, shield_shape(n, 0.045), (212, 175, 55, 255))
    polygon(img, n, shield_shape(n, 0.105), (30, 58, 138, 255))
    line(img, n, n * 0.50, n * 0.25, n * 0.50, n * 0.68, n * 0.08, (255, 255, 255, 240))
    line(img, n, n * 0.35, n * 0.48, n * 0.65, n * 0.48, n * 0.08, (255, 255, 255, 240))
    circle(img, n, n * 0.50, n * 0.20, n * 0.055, (212, 175, 55, 255))


def draw_token(img: bytearray, n: int) -> None:
    round_rect(img, n, n * 0.13, n * 0.28, n * 0.70, n * 0.73, n * 0.12, (10, 125, 105, 255))
    round_rect(img, n, n * 0.22, n * 0.36, n * 0.62, n * 0.65, n * 0.08, (20, 184, 166, 255))
    circle(img, n, n * 0.28, n * 0.50, n * 0.105, (236, 253, 245, 255))
    circle(img, n, n * 0.28, n * 0.50, n * 0.055, (10, 125, 105, 255))
    rect(img, n, n * 0.66, n * 0.39, n * 0.90, n * 0.61, (203, 213, 225, 255))
    rect(img, n, n * 0.83, n * 0.43, n * 0.94, n * 0.57, (148, 163, 184, 255))
    rect(img, n, n * 0.70, n * 0.43, n * 0.75, n * 0.48, (51, 65, 85, 255))
    rect(img, n, n * 0.70, n * 0.52, n * 0.75, n * 0.57, (51, 65, 85, 255))


def draw_control(img: bytearray, n: int) -> None:
    circle(img, n, n * 0.50, n * 0.50, n * 0.43, (15, 23, 42, 255))
    circle(img, n, n * 0.50, n * 0.50, n * 0.34, (30, 41, 59, 255))
    line(img, n, n * 0.50, n * 0.20, n * 0.50, n * 0.48, n * 0.09, (212, 175, 55, 255))
    for deg in range(35, 326, 3):
        rad = math.radians(deg)
        circle(img, n, n * 0.50 + math.cos(rad) * n * 0.24, n * 0.53 + math.sin(rad) * n * 0.24, n * 0.04, (212, 175, 55, 255))


def bmp_payload(img: bytearray, n: int) -> bytes:
    mask_stride = ((n + 31) // 32) * 4
    xor_size = n * n * 4
    header = struct.pack("<IiiHHIIiiII", 40, n, n * 2, 1, 32, 0, xor_size, 0, 0, 0, 0)
    pixels = bytearray()
    for y in range(n - 1, -1, -1):
        for x in range(n):
            i = (y * n + x) * 4
            pixels.extend((img[i + 2], img[i + 1], img[i], img[i + 3]))
    return header + bytes(pixels) + bytes(mask_stride * n)


def make_ico(draw) -> bytes:
    images = []
    for size in SIZES:
        img = canvas(size)
        draw(img, size)
        images.append((size, bmp_payload(img, size)))

    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + len(images) * 16
    entries = bytearray()
    for size, payload in images:
        entries.extend(struct.pack("<BBBBHHII", size if size < 256 else 0, size if size < 256 else 0, 0, 0, 1, 32, len(payload), offset))
        offset += len(payload)
    return header + bytes(entries) + b"".join(payload for _, payload in images)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, draw in (
        ("zerotrust_shield.ico", draw_shield),
        ("token_device.ico", draw_token),
        ("control_panel.ico", draw_control),
    ):
        (OUT / name).write_bytes(make_ico(draw))
        print(OUT / name)


if __name__ == "__main__":
    main()
