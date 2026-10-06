#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mklogo.py - MTK logo.bin image data unpack/pack tool (pure Python stdlib).

This tool handles the image *data* inside the `logo` part of an MKIMG file.
Signature re-signing is handled separately by resign.py.

Layout of the `logo` part data:
    [u32 count][u32 total_size][u32 offset[count]]... zlib chunks
Each chunk decompresses to raw BGRA pixel data; dimensions keyed by decompressed
size. Pixel format is BGRA (MTK logo storage).

Usage:
    python3 mklogo.py -V | --version
    python3 mklogo.py unpack <image> [-o <dir>]
    python3 mklogo.py pack <dir> <template> [-o <out>]

File-name convention:
    unpack writes:  {idx:02d}_{w}x{h}.png   (known size)
                   {idx:02d}_{bytes}.rgba  (unknown size, raw BGRA)
    pack reads:    same naming; the leading 2-digit index selects the chunk.
                    Chunks not present in the directory are kept from <template>.

Input formats for pack:
    PNG and BMP are decoded with the built-in pure-Python decoder. Other formats
    (JPG, GIF, TGA, PPM, WebP, ...) need Pillow (`pip install pillow`) or
    ImageMagick `convert`/`identify` on PATH. An image not matching the chunk's
    target size is center-cropped and/or padded with opaque black (no scaling).
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

PART_MAGIC = 0x58881688
PART_HDR_SIZE = 512
PART_HDR_FORMAT = "<II32sIIIIIIIIII"
IMG_TYPE_GROUP_CERT = 0x02 << 24

# Decompressed size -> (width, height). 4 bytes per pixel (BGRA).
SIZE_MAP = {
    10368000: (1080, 2400),
    10108800: (1080, 2340),
    249200:   (178, 350),
    49444:    (263, 47),
    36864:    (72, 128),
    14592:    (57, 64),
    11520:    (45, 64),
    2104:     (263, 2),
}

IMG_EXTS = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tga',
            '.ppm', '.pgm', '.pbm', '.webp'}

# Cache for decoded source images (keyed by path), so repeated use of the same
# file across many chunks is decoded only once.
_DECODE_CACHE = {}


VERSION = "1.4-dev"


def roundup(value, align):
    if align is None or align <= 0:
        return value
    return ((value + align - 1) // align) * align


# ---------------- MKIMG part_hdr_t parsing ----

class PartHdr:
    def __init__(self, raw):
        v = struct.unpack(PART_HDR_FORMAT, raw[:80])
        self.magic = v[0]
        self.dsize = v[1]
        self.name = v[2].split(b"\0", 1)[0].decode('latin-1')
        self.maddr = v[3]
        self.mode = v[4]
        self.ext_magic = v[5]
        self.hdr_sz = v[6]
        self.hdr_ver = v[7]
        self.img_type = v[8]
        self.img_list_end = v[9]
        self.align_sz = v[10]
        self.dsize_extend = v[11]
        self.maddr_extend = v[12]
        self.raw = bytearray(raw)   # full 512-byte header

    def padded_data_size(self):
        return roundup(self.dsize, self.align_sz)


def parse_parts(data):
    out = []
    off = 0
    while off + PART_HDR_SIZE <= len(data):
        hdr = PartHdr(data[off:off + PART_HDR_SIZE])
        if hdr.magic != PART_MAGIC:
            break
        data_off = off + PART_HDR_SIZE
        out.append({'hdr': hdr, 'off': off, 'data_off': data_off,
                    'data': bytearray(data[data_off:data_off + hdr.dsize])})
        off = data_off + hdr.padded_data_size()
        if hdr.img_list_end:
            break
    return out


# ---------------- PNG encode/decode (pure Python, no PIL) ----

def png_write(path, rgba, w, h):
    raw = bytearray()
    for y in range(h):
        raw.append(0)   # filter: none
        raw += rgba[y * w * 4:(y + 1) * w * 4]

    def chunk(t, d):
        return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)

    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
    png += chunk(b'IDAT', zlib.compress(bytes(raw), 9))
    png += chunk(b'IEND', b'')
    with open(path, 'wb') as f:
        f.write(png)


def _paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)


def png_read(path):
    """Read a PNG, return (w, h, rgba_bytes). 8-bit, non-interlaced,
       color types 0 (gray), 2 (RGB), 4 (gray+alpha), 6 (RGBA)."""
    d = open(path, 'rb').read()
    if d[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('not a PNG: ' + path)
    off = 8
    idat = b''
    w = h = bd = ct = interlace = None
    while off < len(d):
        ln = struct.unpack_from('>I', d, off)[0]
        t = d[off + 4:off + 8]
        if t == b'IHDR':
            w, h, bd, ct, _, _, interlace = struct.unpack_from('>IIBBBBB', d, off + 8)
        elif t == b'IDAT':
            idat += d[off + 8:off + 8 + ln]
        elif t == b'IEND':
            break
        off += 12 + ln
    if bd != 8:
        raise ValueError('only 8-bit depth supported (got %d)' % bd)
    if interlace:
        raise ValueError('interlaced PNG not supported')
    ch = {0: 1, 2: 3, 4: 2, 6: 4}.get(ct)
    if ch is None:
        raise ValueError('unsupported color type %d' % ct)
    raw = zlib.decompress(idat)
    stride = w * ch
    out = bytearray(w * h * 4)
    prev = bytearray(stride)
    pos = 0
    for y in range(h):
        ft = raw[pos]; pos += 1
        line = bytearray(raw[pos:pos + stride]); pos += stride
        if ft == 1:        # sub
            for i in range(ch, stride):
                line[i] = (line[i] + line[i - ch]) & 0xFF
        elif ft == 2:      # up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:      # average
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ft == 4:      # paeth
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                c = prev[i - ch] if i >= ch else 0
                line[i] = (line[i] + _paeth(a, prev[i], c)) & 0xFF
        if ct == 6:
            out[y * w * 4:(y + 1) * w * 4] = line
        elif ct == 2:
            o = y * w * 4
            out[o::4] = line[0::3]; out[o + 1::4] = line[1::3]; out[o + 2::4] = line[2::3]
            out[o + 3::4] = b'\xff' * w
        elif ct == 0:
            o = y * w * 4
            out[o::4] = line; out[o + 1::4] = line; out[o + 2::4] = line
            out[o + 3::4] = b'\xff' * w
        elif ct == 4:
            o = y * w * 4
            out[o::4] = line[0::2]; out[o + 1::4] = line[0::2]; out[o + 2::4] = line[0::2]
            out[o + 3::4] = line[1::2]
        prev = line
    return w, h, bytes(out)


def bmp_read(path):
    """Read a BMP, return (w, h, rgba_bytes). Supports 24/32-bit uncompressed."""
    d = open(path, 'rb').read()
    if d[:2] != b'BM':
        raise ValueError('not a BMP: ' + path)
    off = struct.unpack_from('<I', d, 10)[0]
    w, h = struct.unpack_from('<ii', d, 18)
    bpp = struct.unpack_from('<H', d, 28)[0]
    top = h < 0
    h = abs(h)
    if bpp == 32:
        bgra = bytearray(d[off:off + w * h * 4])
    elif bpp == 24:
        rs = roundup(w * 3, 4)
        bgra = bytearray(w * h * 4)
        for y in range(h):
            s = y * rs
            o = y * w * 4
            for x in range(w):
                bgra[o + x * 4:o + x * 4 + 3] = d[off + s + x * 3:off + s + x * 3 + 3]
                bgra[o + x * 4 + 3] = 0xFF
    else:
        raise ValueError('only 24/32-bit BMP supported (got %d)' % bpp)
    if not top:                                   # bottom-up -> flip
        bgra = bytearray().join(bgra[(h - 1 - y) * w * 4:(h - y) * w * 4] for y in range(h))
    rgba = bytearray(len(bgra))
    rgba[0::4] = bgra[2::4]; rgba[1::4] = bgra[1::4]
    rgba[2::4] = bgra[0::4]; rgba[3::4] = bgra[3::4]
    return w, h, bytes(rgba)


# ---------------- multi-format image loading ----

def _load_via_convert(path):
    """Decode via ImageMagick: identify for size, convert to raw RGBA."""
    out = subprocess.run(['identify', '-format', '%w %h', path + '[0]'],
                         capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.strip():
        raise ValueError('identify failed: ' + out.stderr.strip())
    w, h = map(int, out.stdout.split()[:2])
    tmp = tempfile.NamedTemporaryFile(suffix='.rgba', delete=False).name
    try:
        r = subprocess.run(['convert', path, '-alpha', 'opaque', '-depth', '8',
                            'RGBA:' + tmp], capture_output=True)
        if r.returncode != 0:
            raise ValueError('convert failed: ' + r.stderr.decode('utf-8', 'replace').strip())
        rgba = open(tmp, 'rb').read()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    if len(rgba) != w * h * 4:
        raise ValueError('convert output size %d != %dx%dx4' % (len(rgba), w, h))
    return w, h, rgba


def load_image(path):
    """Load an image as (w, h, rgba_bytes). PNG/BMP are decoded internally;
       other formats require Pillow or ImageMagick `convert`/`identify`.
       Results are cached per path."""
    if path in _DECODE_CACHE:
        return _DECODE_CACHE[path]
    result = None
    try:
        from PIL import Image
        im = Image.open(path).convert('RGBA')
        result = (im.width, im.height, im.tobytes())
    except ImportError:
        pass
    if result is None and shutil.which('convert') and shutil.which('identify'):
        result = _load_via_convert(path)
    if result is None:
        with open(path, 'rb') as f:
            head = f.read(8)
        if head[:8] == b'\x89PNG\r\n\x1a\n':
            result = png_read(path)
        elif head[:2] == b'BM':
            result = bmp_read(path)
    if result is None:
        raise ValueError(
            'cannot decode %s: install Pillow or ImageMagick, or use PNG/BMP'
            % os.path.basename(path))
    _DECODE_CACHE[path] = result
    return result


def fit_rgba(src, sw, sh, dw, dh):
    """Fit source RGBA (sw x sh) into (dw x dh) by center-cropping and/or
       padding with opaque black. No scaling."""
    dst = bytearray(b'\x00\x00\x00\xff' * (dw * dh))
    cw = min(sw, dw)
    ch = min(sh, dh)
    sx = (sw - cw) // 2
    sy = (sh - ch) // 2
    dx = (dw - cw) // 2
    dy = (dh - ch) // 2
    for y in range(ch):
        s_off = ((sy + y) * sw + sx) * 4
        d_off = ((dy + y) * dw + dx) * 4
        dst[d_off:d_off + cw * 4] = src[s_off:s_off + cw * 4]
    return bytes(dst)


def rgba_to_bgra(rgba):
    b = bytearray(len(rgba))
    b[0::4] = rgba[2::4]
    b[1::4] = rgba[1::4]
    b[2::4] = rgba[0::4]
    b[3::4] = rgba[3::4]
    return bytes(b)


def bgra_to_rgba(bgra):
    b = bytearray(len(bgra))
    b[0::4] = bgra[2::4]
    b[1::4] = bgra[1::4]
    b[2::4] = bgra[0::4]
    b[3::4] = bgra[3::4]
    return bytes(b)


# ---------------- logo payload helpers ----

def parse_logo_payload(pay):
    cnt, total = struct.unpack_from('<II', pay, 0)
    offs = [struct.unpack_from('<I', pay, 8 + i * 4)[0] for i in range(cnt)]
    return cnt, total, offs


def iter_chunks(pay, cnt, offs, total):
    for i in range(cnt):
        end = offs[i + 1] if i + 1 < cnt else total
        yield i, pay[offs[i]:end]


# ---------------- commands ----

def cmd_unpack(args):
    image = Path(args.image)
    out_dir = Path(args.out) if args.out else Path.cwd() / (image.stem + '_out')
    out_dir.mkdir(parents=True, exist_ok=True)
    data = image.read_bytes()
    parts = parse_parts(data)
    li = next((i for i, p in enumerate(parts) if p['hdr'].name == 'logo'), None)
    if li is None:
        print('[ERROR] no logo part found')
        return 1
    pay = bytes(parts[li]['data'])
    cnt, total, offs = parse_logo_payload(pay)
    print(f'Image: {image.name}  parts={len(parts)}  logo chunks={cnt}  payload={len(pay)}')
    unknown = []
    for i, raw in iter_chunks(pay, cnt, offs, total):
        try:
            dec = zlib.decompress(raw)
        except Exception as e:
            print(f'[{i:02d}] decompress error: {e}')
            continue
        wh = SIZE_MAP.get(len(dec))
        if wh is None:
            fn = out_dir / f'{i:02d}_{len(dec)}.rgba'
            fn.write_bytes(dec)
            unknown.append((i, len(dec)))
            print(f'[{i:02d}] UNKNOWN size={len(dec)} px={len(dec)//4} -> {fn.name}')
            continue
        w, h = wh
        rgba = bgra_to_rgba(dec)
        fn = out_dir / f'{i:02d}_{w}x{h}.png'
        png_write(str(fn), rgba, w, h)
        print(f'[{i:02d}] {w}x{h}  comp={len(raw)} dec={len(dec)} -> {fn.name}')
    print(f'\n[OK] {cnt} chunks -> {out_dir}')
    if unknown:
        print('Unknown sizes (saved as .rgba, repacked verbatim if untouched):')
        for i, sz in unknown:
            print(f'  [{i:02d}] {sz} bytes')
    return 0


def _collect_pack_sources(src_dir, cnt):
    """Return {idx: (ext, path)} for files whose 2-digit prefix matches a chunk
       index. Recognizes image extensions plus .rgba. First file per index wins."""
    sources = {}
    for p in sorted(src_dir.iterdir()):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext not in IMG_EXTS and ext != '.rgba':
            continue
        try:
            idx = int(p.name.split('_')[0])
        except (ValueError, IndexError):
            continue
        if idx < 0 or idx >= cnt:
            continue
        if idx in sources:
            continue
        sources[idx] = (ext, p)
    return sources


def cmd_pack(args):
    src_dir = Path(args.dir)
    template = Path(args.template)
    out = Path(args.out) if args.out else template.with_suffix(template.suffix + '.packed')
    if not src_dir.is_dir():
        print(f'[ERROR] not a directory: {src_dir}')
        return 2
    if not template.exists():
        print(f'[ERROR] template not found: {template}')
        return 2
    data = template.read_bytes()
    parts = parse_parts(data)
    li = next((i for i, p in enumerate(parts) if p['hdr'].name == 'logo'), None)
    if li is None:
        print('[ERROR] no logo part in template')
        return 1
    pay = bytes(parts[li]['data'])
    cnt, total, offs = parse_logo_payload(pay)
    sources = _collect_pack_sources(src_dir, cnt)
    print(f'Template: {template.name}  chunks={cnt}  provided={len(sources)}')

    blocks = []
    replaced = 0
    for i, raw in iter_chunks(pay, cnt, offs, total):
        src = sources.get(i)
        if src is None:
            blocks.append(raw)          # keep original compressed chunk
            continue
        ext, path = src
        if ext == '.rgba':
            bgra = path.read_bytes()
            blocks.append(zlib.compress(bgra, 9))
            replaced += 1
            print(f'[{i:02d}] <- {path.name} (rgba)  comp={len(blocks[-1])}')
            continue
        # image: decode, fit to target, convert to BGRA
        try:
            dec = zlib.decompress(raw)
        except Exception as e:
            print(f'[{i:02d}] template chunk decompress error: {e}; keeping original')
            blocks.append(raw)
            continue
        wh = SIZE_MAP.get(len(dec))
        if wh is None:
            print(f'[{i:02d}] target size unknown (dec={len(dec)}); keeping original')
            blocks.append(raw)
            continue
        dw, dh = wh
        sw, sh, rgba = load_image(str(path))
        if (sw, sh) != (dw, dh):
            rgba = fit_rgba(rgba, sw, sh, dw, dh)
            print(f'[{i:02d}] fit {sw}x{sh} -> {dw}x{dh}  ({path.name})')
        bgra = rgba_to_bgra(rgba)
        blocks.append(zlib.compress(bgra, 9))
        replaced += 1
        print(f'[{i:02d}] <- {path.name}  comp={len(blocks[-1])}')
    print(f'Replaced {replaced}/{cnt} chunks')

    # rebuild payload: [count][total][offsets][blocks]
    head = 8 + cnt * 4
    cur = head
    noff = []
    body = bytearray()
    for b in blocks:
        noff.append(cur)
        cur += len(b)
        body += b
    newpay = bytearray(struct.pack('<II', cnt, cur))
    for o in noff:
        newpay += struct.pack('<I', o)
    newpay += body
    parts[li]['data'] = newpay
    parts[li]['hdr'].dsize = len(newpay)
    print(f'New logo payload: {len(newpay)} bytes (was {len(pay)})')

    # repack whole MKIMG
    out_bytes = bytearray()
    for p in parts:
        h = p['hdr']
        hraw = bytearray(h.raw)
        struct.pack_into('<I', hraw, 4, h.dsize)   # update dsize
        out_bytes += hraw
        out_bytes += p['data']
        pad = roundup(h.dsize, h.align_sz) - len(p['data'])
        out_bytes += b'\x00' * pad
    out.write_bytes(out_bytes)
    print(f'[OK] written: {out} ({len(out_bytes)} bytes)')
    print('Next: sign with  resign.py install ' + str(out))
    return 0


def main():
    p = argparse.ArgumentParser(
        prog='mklogo.py',
        description='MTK logo.bin image data unpack/pack tool (pure Python stdlib)',
    )
    p.add_argument('-V', '--version', action='store_true', help='show version')
    sub = p.add_subparsers(dest='cmd')

    pu = sub.add_parser('unpack', help='extract logo chunks to PNG/.rgba')
    pu.add_argument('image', help='input logo image file')
    pu.add_argument('-o', '--out', help='output directory (default <stem>_out)')
    pu.set_defaults(func=cmd_unpack)

    pc = sub.add_parser('pack', help='repack images into a logo image (multi-format, auto fit)')
    pc.add_argument('dir', help='directory of edited chunks (indexed by filename prefix)')
    pc.add_argument('template', help='original logo image as template')
    pc.add_argument('-o', '--out', help='output file (default <template>.packed)')
    pc.set_defaults(func=cmd_pack)

    args = p.parse_args()
    if args.version:
        print(f'mklogo.py {VERSION}')
        return 0
    if not getattr(args, 'func', None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
