#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core.py - MTK logo image toolchain (single-file).

Merges the functionality of mklogo.py (image data unpack/pack) and resign.py
(CERT2 fake-cert install/verify) into one module. The original scripts remain
unchanged; this file is a unified entry point and shared library.

Subcommands:
    unpack   extract logo chunks to PNG/.rgba
    pack     repack images into a logo image (multi-format, auto fit)
    install  inject legacy fake cert into an image (bypass_mode=1)
    verify   check that a fake cert is installed and hashes match

Usage:
    python3 core.py -V | --version
    python3 core.py unpack <image> [-o <dir>]
    python3 core.py pack <dir> <template> [-o <out>]
    python3 core.py install <img> [-o <out>]
    python3 core.py build <dir> <template> [-o <out>]
    python3 core.py verify <img>

How the fake cert works (legacy, bypass_mode=1):
    MTK libsec has a logic flaw when verifying CERT2: in bypass_mode=1 (old
    V5/V6 libsec), the ASN.1 parser steps into every object it meets. So a fake
    BIT STRING placed at the front of the CERT2 DER is entered, and the real
    certificate SEQUENCE nested inside it is then walked as usual.
    `install` prepends two sibling blocks before the original CERT2 DER:
        1. BIT STRING(original CERT2 DER)   -- the legacy wrapper libsec steps into
        2. 0xA0 { OID 2.16.886.2454.2.4 + BIT STRING(new header hash)
                 OID 2.16.886.2454.2.1 + BIT STRING(new image  hash) }
    libsec finds the hash override first and trusts it, ignoring the real signed
    content, so a modified image still passes verification.
"""
import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

VERSION = "1.4-dev"

PART_MAGIC = 0x58881688
PART_HDR_SIZE = 512
PART_HDR_FORMAT = "<II32sIIIIIIIIII"
IMG_TYPE_GROUP_CERT = 0x02 << 24
IMG_TYPE_CERT2 = IMG_TYPE_GROUP_CERT | 0x02
OID_IMAGE_HASH = '2.16.886.2454.2.1'
OID_IMAGE_HEADER_HASH = '2.16.886.2454.2.4'

# Decompressed size -> (width, height). 4 bytes per pixel (BGRA).
SIZE_MAP = {
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

_DECODE_CACHE = {}


def roundup(value, align):
    if align is None or align <= 0:
        return value
    return ((value + align - 1) // align) * align


# ---------------- DER encode/decode (pure Python) ----

def read_tag(data, off):
    b0 = data[off]
    tag_class = (b0 & 0xC0) >> 6
    constructed = bool(b0 & 0x20)
    tagnum = b0 & 0x1F
    tag_bytes = bytes([b0])
    i = off + 1
    if tagnum == 0x1F:                         # long-form tag number
        tagnum = 0
        while True:
            if i >= len(data):
                raise ValueError('Truncated long-form tag')
            b = data[i]
            tag_bytes += bytes([b])
            tagnum = (tagnum << 7) | (b & 0x7F)
            i += 1
            if not (b & 0x80):
                break
    return tag_class, constructed, tagnum, tag_bytes, i - off


def read_length(data, off):
    if off >= len(data):
        raise ValueError('Truncated length')
    b = data[off]
    if not (b & 0x80):
        return b, 1                            # short form
    num = b & 0x7F
    if num == 0:
        return None, 1                         # indefinite length (BER), not expected in DER
    if off + 1 + num > len(data):
        raise ValueError('Truncated length bytes')
    val = 0
    for i in range(num):
        val = (val << 8) | data[off + 1 + i]
    return val, 1 + num


def decode_oid(oid_bytes):
    if not oid_bytes:
        return ''
    first = oid_bytes[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
    return '.'.join(parts)


def encode_length(n):
    if n < 0x80:
        return bytes([n])
    s = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(s)]) + s


def encode_oid(oid):
    parts = [int(x) for x in oid.split('.')]
    if len(parts) < 2:
        raise ValueError('bad oid')
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        chunks = []
        while p > 0:
            chunks.insert(0, p & 0x7F)
            p >>= 7
        for i, v in enumerate(chunks):
            out.append(0x80 | v if i != len(chunks) - 1 else v)
    return bytes(out)


def build_oid_tlv(oid):
    b = encode_oid(oid)
    return b'\x06' + encode_length(len(b)) + b


def build_bitstring_tlv(payload):
    val = b'\x00' + payload                    # 0 unused bits prefix
    return b'\x03' + encode_length(len(val)) + val


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


# ---------------- pure-Python image decoders (RGB) ----
# Fallback for when Pillow is unavailable (e.g. onefile on Android, where the
# PIL C extensions cannot find their bundled .so deps). Return (w, h, rgb).
# Adapted from img2png.py; ASCII-only.

_ZIG = [0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5,12,19,26,33,40,48,41,34,27,20,13,6,7,14,
       21,28,35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51,58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63]


def _dec_jpeg(d):
    qt = {}; huff = {}; sof = None; pos = 2
    while pos < len(d) - 1:
        if d[pos] != 0xFF:
            pos += 1; continue
        while pos < len(d) and d[pos] == 0xFF: pos += 1
        if pos >= len(d): break
        m = d[pos]; pos += 1
        if m == 0xD8 or m == 0x01 or 0xD0 <= m <= 0xD7: continue
        if m == 0xD9: break
        ln = struct.unpack_from('>H', d, pos)[0]
        seg = d[pos+2:pos+ln]
        if m == 0xDB:
            i = 0
            while i < len(seg):
                pq = seg[i] >> 4; tq = seg[i] & 15; i += 1
                t = [0]*64
                for k in range(64):
                    if pq: t[k] = struct.unpack_from('>H', seg, i)[0]; i += 2
                    else:  t[k] = seg[i]; i += 1
                qt[tq] = t
        elif m == 0xC4:
            i = 0
            while i < len(seg):
                tc = seg[i] >> 4; th = seg[i] & 15; i += 1
                cnts = list(seg[i:i+16]); i += 16
                syms = list(seg[i:i+sum(cnts)]); i += sum(cnts)
                tbl = {}; code = 0; p = 0
                for L in range(16):
                    for _ in range(cnts[L]):
                        tbl[(L+1, code)] = syms[p]; p += 1; code += 1
                    code <<= 1
                huff[(tc, th)] = tbl
        elif m in (0xC0, 0xC1, 0xC2, 0xC3):
            if m != 0xC0:
                raise ValueError('progressive/other JPEG not supported (not baseline)')
            hh = struct.unpack_from('>H', seg, 1)[0]; ww = struct.unpack_from('>H', seg, 3)[0]
            nc = seg[5]; comps = []
            for k in range(nc):
                cid = seg[6+k*3]; hv = seg[7+k*3]; tq = seg[8+k*3]
                comps.append([cid, hv >> 4, hv & 15, 0, 0, tq, 0])
            sof = [ww, hh, comps]
        elif m == 0xDA:
            if sof is None: raise ValueError('JPEG missing SOF')
            ns = seg[0]; sel = {}
            for k in range(ns):
                sel[seg[1+k*2]] = (seg[2+k*2] >> 4, seg[2+k*2] & 15)
            for c in sof[2]:
                dc, ac = sel.get(c[0], (0, 0)); c[3] = dc; c[4] = ac
            data = d[pos+ln:]
            e = data.find(b'\xff\xd9')
            if e >= 0: data = data[:e]
            return _jpeg_scan(data, qt, huff, sof)
        pos += ln
    raise ValueError('JPEG parse failed')


def _jpeg_scan(data, qt, huff, sof):
    import math
    W, H, comps = sof
    hmax = max(c[1] for c in comps); vmax = max(c[2] for c in comps)
    mcux = (W + 8*hmax - 1)//(8*hmax); mcuy = (H + 8*vmax - 1)//(8*vmax)
    planes = [bytearray(mcux*c[1]*8 * (mcuy*c[2]*8)) for c in comps]
    bi = [0]; bc = [0]; bn = [0]
    def bit():
        if bn[0] == 0:
            if bi[0] >= len(data): return 0
            v = data[bi[0]]; bi[0] += 1
            if v == 0xFF:
                nx = data[bi[0]] if bi[0] < len(data) else 0
                if nx == 0: bi[0] += 1
                else: return 0
            bc[0] = v; bn[0] = 8
        bn[0] -= 1
        return (bc[0] >> bn[0]) & 1
    def nbits(n):
        v = 0
        for _ in range(n): v = (v << 1) | bit()
        return v
    def hdec(t):
        code = 0
        for L in range(1, 17):
            code = (code << 1) | bit()
            x = t.get((L, code))
            if x is not None: return x
        return 0
    def ext(v, n): return v - (1 << n) + 1 if (n and v < (1 << (n-1))) else v
    C = [[math.cos((2*x+1)*u*math.pi/16) * (0.35355339059327373 if u == 0 else 0.5)
          for u in range(8)] for x in range(8)]
    def idct(blk):
        tmp = [0.0]*64
        for u in range(8):
            for y in range(8):
                cy = C[y]; s = 0.0
                for v in range(8): s += cy[v]*blk[v*8+u]
                tmp[u*8+y] = s
        o = [0.0]*64
        for y in range(8):
            for x in range(8):
                cx = C[x]; s = 0.0
                for u in range(8): s += cx[u]*tmp[u*8+y]
                o[y*8+x] = s
        return o
    _cache = {}
    dcT = []; acT = []
    for c in comps:
        t1 = huff.get((0, c[3])); t2 = huff.get((1, c[4]))
        if not t1: raise ValueError('missing DC huffman table %d' % c[3])
        if not t2: raise ValueError('missing AC huffman table %d' % c[4])
        dcT.append(t1); acT.append(t2)
    for my in range(mcuy):
        for mx in range(mcux):
            for ci, c in enumerate(comps):
                q = qt.get(c[5])
                if q is None: raise ValueError('missing quant table %d' % c[5])
                bw = mcux*c[1]*8
                for by in range(c[2]):
                    for bx in range(c[1]):
                        t = hdec(dcT[ci]); diff = ext(nbits(t), t) if t else 0
                        c[6] += diff
                        blk = [0]*64; blk[0] = c[6]*q[0]
                        k = 1
                        while k < 64:
                            rs = hdec(acT[ci]); r = rs >> 4; s = rs & 15
                            if s == 0:
                                if r == 15: k += 16; continue
                                break
                            k += r
                            if k > 63: break
                            blk[ZIG[k]] = ext(nbits(s), s)*q[k]; k += 1
                        key = tuple(blk)
                        px = _cache.get(key)
                        if px is None:
                            px = idct(blk); _cache[key] = px
                        x0 = (mx*c[1]+bx)*8; y0 = (my*c[2]+by)*8
                        pl = planes[ci]
                        for yy in range(8):
                            base = (y0+yy)*bw + x0
                            for xx in range(8):
                                v = int(px[yy*8+xx] + 128.5)
                                pl[base+xx] = 0 if v < 0 else (255 if v > 255 else v)
    def up_h(p, bw, bh, r):
        fw = bw*r
        o = bytearray(fw*bh)
        for y in range(bh):
            b = y*bw
            for x in range(bw):
                v = p[b+x]
                l = p[b+x-1] if x > 0 else v
                rr = p[b+x+1] if x+1 < bw else v
                for k in range(r):
                    w2 = (k*2+1)
                    o[y*fw + x*r + k] = (v*(2*r-w2) + (l if k < r/2 else rr)*w2 + r) // (2*r)
        return o, fw
    def up_v(p, bw, bh, r):
        fh = bh*r
        o = bytearray(bw*fh)
        for x in range(bw):
            for y in range(bh):
                v = p[y*bw+x]
                u = p[(y-1)*bw+x] if y > 0 else v
                d = p[(y+1)*bw+x] if y+1 < bh else v
                for k in range(r):
                    w2 = (k*2+1)
                    o[(y*r+k)*bw + x] = (v*(2*r-w2) + (u if k < r/2 else d)*w2 + r) // (2*r)
        return o, fh
    full = []
    for ci, c in enumerate(comps):
        bw = mcux*c[1]*8; bh = mcuy*c[2]*8
        p = bytes(planes[ci])
        fw, fh = bw, bh
        if c[1] < hmax:
            r = hmax // c[1]
            p, fw = up_h(p, bw, bh, r)
        if c[2] < vmax:
            r = vmax // c[2]
            p, fh = up_v(p, fw, bh, r)
        if fw == bw and fh == bh:
            full.append(bytes(planes[ci]))
        else:
            full.append(p)
    fw = mcux*hmax*8
    out = bytearray(W*H*3)
    for y in range(H):
        for x in range(W):
            vals = []
            for ci, c in enumerate(comps):
                vals.append(full[ci][y*fw+x])
            if len(vals) == 1:
                r = g = b = vals[0]
            elif len(vals) >= 3:
                Y = vals[0]; Cb = vals[1]-128; Cr = vals[2]-128
                r = Y + 1.402*Cr; g = Y - 0.344136*Cb - 0.714136*Cr; b = Y + 1.772*Cb
            else:
                r = g = b = vals[0]
            o = (y*W+x)*3
            out[o] = 0 if r < 0 else (255 if r > 255 else int(r))
            out[o+1] = 0 if g < 0 else (255 if g > 255 else int(g))
            out[o+2] = 0 if b < 0 else (255 if b > 255 else int(b))
    return W, H, bytes(out)


def _dec_gif(d):
    w, h = struct.unpack_from('<HH', d, 6)
    flg = d[10]
    pos = 13
    gct = []
    if flg & 0x80:
        n = 2 << (flg & 7); gct = [tuple(d[pos+i*3:pos+i*3+3]) for i in range(n)]; pos += n*3
    out = bytearray(w*h*3)
    def lzw(p, minc):
        tbl = [bytes([i]) for i in range(1 << minc)] + [b'', b'']
        cs = minc+1; prev = None; res = []
        data = p; acc = 0; nb = 0; i = 0
        while i < len(data):
            acc |= data[i] << nb; nb += 8; i += 1
            while nb >= cs:
                code = acc & ((1 << cs) - 1); acc >>= cs; nb -= cs
                if code == (1 << minc): return res
                if code < len(tbl) and tbl[code]: e = tbl[code]
                elif prev is not None: e = prev + prev[:1]
                else: continue
                res.append(e)
                if prev is not None:
                    tbl.append(prev + e[:1])
                    if len(tbl) == (1 << cs) and cs < 12: cs += 1
                prev = e
        return res
    while pos < len(d):
        b = d[pos]; pos += 1
        if b == 0x3B: break
        if b == 0x21:
            pos += 1
            while pos < len(d) and d[pos]: pos += d[pos]+1
            pos += 1
        elif b == 0x2C:
            ix, iy, iw, ih = struct.unpack_from('<HHHH', d, pos); pos += 8
            lf = d[pos]; pos += 1
            lct = []
            if lf & 0x80:
                n = 2 << (lf & 7); lct = [tuple(d[pos+i*3:pos+i*3+3]) for i in range(n)]; pos += n*3
            minc = d[pos]; pos += 1
            sub = b''
            while pos < len(d) and d[pos]:
                ln = d[pos]; pos += 1; sub += d[pos:pos+ln]; pos += ln
            pos += 1
            pal = lct or gct
            idx = lzw(sub, minc)
            for y in range(ih):
                for x in range(iw):
                    k = y*iw+x
                    if k >= len(idx): break
                    c = idx[k][0] if idx[k] else 0
                    if c >= len(pal): r=g=b=0
                    else: r,g,b = pal[c]
                    px, py = ix+x, iy+y
                    if px < w and py < h:
                        o = (py*w+px)*3; out[o],out[o+1],out[o+2] = r,g,b
    return w, h, bytes(out)


def _dec_tga(d):
    idl, cmap, typ = d[0], d[1], d[2]
    w, h = struct.unpack_from('<HH', d, 12)
    bpp = d[16]
    pos = 18 + idl
    out = bytearray(w*h*3)
    step = 4 if bpp == 32 else 3
    for y in range(h):
        for x in range(w):
            p = pos + (y*w+x)*step
            if p+step > len(d): break
            o = ((h-1-y)*w+x)*3
            out[o] = d[p+2]; out[o+1] = d[p+1]; out[o+2] = d[p]
    return w, h, bytes(out)


def _dec_pnm(d):
    toks = []; i = 0
    while len(toks) < 4 and i < len(d):
        while i < len(d) and d[i:i+1].isspace(): i += 1
        if d[i:i+1] == b'#':
            while i < len(d) and d[i:i+1] != b'\n': i += 1
            continue
        j = i
        while j < len(d) and not d[j:j+1].isspace(): j += 1
        toks.append(d[i:j]); i = j
    i += 1
    magic = toks[0]; w = int(toks[1]); h = int(toks[2])
    out = bytearray(w*h*3)
    if magic == b'P6':
        out[:] = d[i:i+w*h*3]
    elif magic == b'P5':
        for k in range(w*h):
            v = d[i+k]; out[k*3]=out[k*3+1]=out[k*3+2]=v
    else: raise ValueError('PNM format not supported')
    return w, h, bytes(out)


def _sniff(head):
    if head[:8] == b'\x89PNG\r\n\x1a\n': return 'png'
    if head[:2] == b'BM': return 'bmp'
    if head[:3] == b'GIF': return 'gif'
    if head[:2] == b'\xff\xd8': return 'jpg'
    if head[:2] in (b'P1', b'P4', b'P2', b'P3', b'P5', b'P6'): return 'pnm'
    return 'tga'


def _rgb_to_rgba(rgb):
    n = len(rgb) // 3
    out = bytearray(n * 4)
    out[0::4] = rgb[0::3]
    out[1::4] = rgb[1::3]
    out[2::4] = rgb[2::3]
    out[3::4] = b'\xff' * n
    return bytes(out)


# ---------------- pixel format conversion ----

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
    """Load an image as (w, h, rgba_bytes). Pillow first (best, most formats);
       on any failure (e.g. PIL C extensions can't find their .so deps in an
       onefile on Android), fall back to pure-Python decoders for
       PNG/BMP/JPG/GIF/TGA/PNM; finally try ImageMagick convert/identify.
       Results are cached per path."""
    if path in _DECODE_CACHE:
        return _DECODE_CACHE[path]
    result = None
    try:
        from PIL import Image
        im = Image.open(path).convert('RGBA')
        result = (im.width, im.height, im.tobytes())
    except Exception:
        pass
    if result is None and shutil.which('convert') and shutil.which('identify'):
        try:
            result = _load_via_convert(path)
        except Exception:
            pass
    if result is None:
        try:
            with open(path, 'rb') as f:
                head = f.read(8)
            kind = _sniff(head)
            if kind == 'png':
                w, h, rgba = png_read(path)
                result = (w, h, rgba)
            elif kind == 'bmp':
                w, h, rgba = bmp_read(path)
                result = (w, h, rgba)
            else:
                data = open(path, 'rb').read()
                if kind == 'jpg':
                    w, h, rgb = _dec_jpeg(data)
                elif kind == 'gif':
                    w, h, rgb = _dec_gif(data)
                elif kind == 'tga':
                    w, h, rgb = _dec_tga(data)
                elif kind == 'pnm':
                    w, h, rgb = _dec_pnm(data)
                else:
                    raise ValueError('unknown image format')
                result = (w, h, _rgb_to_rgba(rgb))
        except Exception as e:
            sys.stderr.write('[load_image] %s: %s\n' % (os.path.basename(path), e))
    if result is None:
        raise ValueError('cannot decode %s' % os.path.basename(path))
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


# ---------------- DER tree parsing / lookup ----

def parse_tlv_tree(data, base_off=0):
    nodes = []
    off = 0
    L = len(data)
    while off < L:
        try:
            tag_class, constructed, tagnum, tag_bytes, tag_len = read_tag(data, off)
            length, len_len = read_length(data, off + tag_len)
        except Exception:
            break
        hdr_len = tag_len + len_len
        val_off = off + hdr_len
        val_end = val_off + length
        if length is None or val_end > L:
            break
        val = data[val_off:val_end]
        node = {
            'off': base_off + off,
            'tag_class': tag_class,
            'constructed': constructed,
            'tagnum': tagnum,
            'hdr_len': hdr_len,
            'length': length,
            'val': None if constructed else val,
            'children': parse_tlv_tree(val, base_off + val_off) if constructed else None,
        }
        nodes.append(node)
        off = val_end
    return nodes


def _find_bitstring_in_node(node):
    if node is None:
        return None
    if node['tag_class'] == 0 and node['tagnum'] == 3 and node['val'] is not None:
        return node['val']
    if node.get('children'):
        for ch in node['children']:
            res = _find_bitstring_in_node(ch)
            if res is not None:
                return res
    return None


def find_oid_bitstring(der, oid_str):
    """Find the given OID anywhere in the DER nest; return the following BIT STRING
       (with unused-bits prefix) or None."""
    root_nodes = parse_tlv_tree(der, base_off=0)

    def walk(nodes):
        for i, node in enumerate(nodes):
            if node['tag_class'] == 0 and node['tagnum'] == 6 and node['val'] is not None:
                try:
                    name = decode_oid(node['val'])
                except Exception:
                    name = ''
                if name == oid_str:
                    for j in range(i + 1, len(nodes)):
                        bs = _find_bitstring_in_node(nodes[j])
                        if bs is not None:
                            return bs
                    return None
            if node.get('children'):
                res = walk(node['children'])
                if res is not None:
                    return res
        return None

    return walk(root_nodes)


def find_first_tlv(data):
    """Parse the first TLV at the start of data; return
       (tag_class, constructed, tagnum, val_off, val_end) or None."""
    if not data:
        return None
    try:
        tag_class, constructed, tagnum, tag_bytes, tag_len = read_tag(data, 0)
        length, len_len = read_length(data, tag_len)
    except Exception:
        return None
    if length is None:
        return None
    val_off = tag_len + len_len
    val_end = val_off + length
    if val_end > len(data):
        return None
    return tag_class, constructed, tagnum, val_off, val_end


def iter_top_level_tlvs(data):
    off = 0
    while off < len(data):
        first = find_first_tlv(data[off:])
        if not first:
            break
        tag_class, constructed, tagnum, val_off, val_end = first
        yield {
            'off': off,
            'end': off + val_end,
            'tag_class': tag_class,
            'constructed': constructed,
            'tagnum': tagnum,
            'val_off': off + val_off,
        }
        off += val_end


def find_original_cert2_der(der):
    """Locate the original CERT2 DER SEQUENCE (0x30) in the blob.
       Returns (der_bytes, rel_offset)."""
    for node in iter_top_level_tlvs(der):
        if node['tag_class'] == 0 and node['constructed'] and node['tagnum'] == 0x10:
            return der[node['off']:node['end']], node['off']
    raise ValueError('original CERT2 DER SEQUENCE (0x30) not found')


def recover_original_der(der):
    """Strip any legacy BIT STRING wrapper and 0xA0 override block prepended by a
       previous install, so re-installing is idempotent. Stops at the first 0x30
       SEQUENCE (the real CERT2 root)."""
    while True:
        first = find_first_tlv(der)
        if not first:
            break
        is_bitstring = (first[0] == 0 and first[2] == 3)        # universal BIT STRING
        is_override = (first[0] == 2 and first[1] and first[2] == 0)  # ctx cons tag 0 (0xA0)
        if is_bitstring or is_override:
            der = der[first[4]:]
        else:
            break
    return der


# ---------------- CERT2 hash override / writeback ----

def build_hash_override_block(header_digest, image_digest):
    parts = []
    if header_digest is not None:
        parts.append(build_oid_tlv(OID_IMAGE_HEADER_HASH))
        parts.append(build_bitstring_tlv(header_digest))
    if image_digest is not None:
        parts.append(build_oid_tlv(OID_IMAGE_HASH))
        parts.append(build_bitstring_tlv(image_digest))
    if not parts:
        return b''
    inner = b''.join(parts)
    return b'\xa0' + encode_length(len(inner)) + inner


def replace_cert2_blob(data, c_blob_off, c_off, c_hdr, new_blob):
    new_dsz = len(new_blob)
    old_padded = c_hdr.padded_data_size()
    new_padded = roundup(new_dsz, c_hdr.align_sz)
    new_blob_padded = new_blob + b'\x00' * (new_padded - len(new_blob))
    out = bytearray(data)
    out[c_blob_off:c_blob_off + old_padded] = new_blob_padded
    struct.pack_into('<I', out, c_off + 4, new_dsz)   # update part_hdr.dsize
    return bytes(out)


def find_cert2_and_target(parts):
    cert2_entry = None
    for idx, p in enumerate(parts):
        hdr = p['hdr']
        if hdr.img_type == IMG_TYPE_CERT2:
            next_off = parts[idx + 1]['off'] if idx + 1 < len(parts) else None
            cert2_entry = (idx, p['off'], p['data_off'], next_off, hdr)
            break
    if not cert2_entry:
        return None, None
    c_off = cert2_entry[1]
    target_part = None
    for idx, p in enumerate(parts):
        if p['off'] < c_off and (p['hdr'].img_type & 0xff000000) != IMG_TYPE_GROUP_CERT:
            next_off = parts[idx + 1]['off'] if idx + 1 < len(parts) else None
            target_part = (idx, p['off'], p['data_off'], next_off, p['hdr'])   # last non-cert image before CERT2
    return cert2_entry, target_part


def compute_hash_inputs(data, target_part):
    _, t_off, t_data_off, _, t_hdr = target_part
    img_hdr_sz = t_hdr.hdr_sz if t_hdr.hdr_sz else PART_HDR_SIZE
    header_bytes = data[t_off:t_off + img_hdr_sz]
    padded_size = t_hdr.padded_data_size()
    data_bytes = data[t_data_off:t_data_off + padded_size]
    return header_bytes, data_bytes


def alg_from_len(n):
    return 'sha256' if n == 32 else ('sha384' if n == 48 else None)


# ---------------- logo payload helpers ----

def parse_logo_payload(pay):
    cnt, total = struct.unpack_from('<II', pay, 0)
    offs = [struct.unpack_from('<I', pay, 8 + i * 4)[0] for i in range(cnt)]
    return cnt, total, offs


def iter_chunks(pay, cnt, offs, total):
    for i in range(cnt):
        end = offs[i + 1] if i + 1 < cnt else total
        yield i, pay[offs[i]:end]


# ---------------- commands: unpack / pack ----

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


def pack_image(src_dir, template):
    """Pack images from src_dir into the template MKIMG; return new image bytes.
       Prints per-chunk progress."""
    data = template.read_bytes()
    parts = parse_parts(data)
    li = next((i for i, p in enumerate(parts) if p['hdr'].name == 'logo'), None)
    if li is None:
        raise ValueError('no logo part in template')
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
    return bytes(out_bytes)


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
    out_bytes = pack_image(src_dir, template)
    out.write_bytes(out_bytes)
    print(f'[OK] written: {out} ({len(out_bytes)} bytes)')
    print('Next: sign with  core.py install ' + str(out))
    return 0


# ---------------- commands: install / verify ----

def install_image(data):
    """Inject legacy fake cert into image bytes; return signed image bytes.
       Prints CERT2/hash/override progress."""
    print(f"Image: {len(data)} bytes")

    parts = parse_parts(data)
    if not parts:
        raise ValueError('no part_hdr_t headers found')

    cert2_entry, target_part = find_cert2_and_target(parts)
    if not cert2_entry:
        raise ValueError('CERT2 partition header not found')
    if not target_part:
        raise ValueError('no target image partition found before CERT2; cannot compute hashes')

    _, c_off, c_blob_off, _, c_hdr = cert2_entry
    der = data[c_blob_off:c_blob_off + c_hdr.dsize]
    print(f'CERT2: off=0x{c_off:08x}  blob=0x{c_blob_off:08x}  dsize={c_hdr.dsize}')

    # Idempotent: strip any legacy wrapper / override block from a previous install
    recovered = recover_original_der(der)
    if len(recovered) != len(der):
        print(f'[INFO] existing legacy prefix detected and stripped ({len(der) - len(recovered)} bytes); will re-inject')

    # Original CERT2 DER SEQUENCE (0x30) that the legacy wrapper must enclose
    original_cert2_der, original_rel = find_original_cert2_der(recovered)
    print(f'Original CERT2 DER at rel=0x{original_rel:x}, size={len(original_cert2_der)}')

    # Identify hash algorithm from the original DER
    hdr_bit = find_oid_bitstring(recovered, OID_IMAGE_HEADER_HASH)
    img_bit = find_oid_bitstring(recovered, OID_IMAGE_HASH)
    if hdr_bit is None or img_bit is None or len(hdr_bit) < 1 or len(img_bit) < 1:
        raise ValueError('Image Header Hash / Image Hash OID not found in CERT2')
    old_hdr_digest = hdr_bit[1:]
    old_img_digest = img_bit[1:]
    alg = alg_from_len(len(old_hdr_digest)) or alg_from_len(len(old_img_digest))
    if alg is None:
        raise ValueError(f'cannot identify hash algorithm (header len={len(old_hdr_digest)}, image len={len(old_img_digest)})')
    hfn = hashlib.sha256 if alg == 'sha256' else hashlib.sha384

    header_bytes, data_bytes = compute_hash_inputs(data, target_part)
    new_hdr_digest = hfn(header_bytes).digest()
    new_img_digest = hfn(data_bytes).digest()
    print(f'Algorithm: {alg}')
    print(f'  old header hash: {old_hdr_digest.hex()}')
    print(f'  new header hash: {new_hdr_digest.hex()}')
    print(f'  old image  hash: {old_img_digest.hex()}')
    print(f'  new image  hash: {new_img_digest.hex()}')

    # Legacy prefix: BIT STRING(original DER) + 0xA0 hash override, placed before the original DER
    legacy_block = build_bitstring_tlv(original_cert2_der)
    insert_block = build_hash_override_block(new_hdr_digest, new_img_digest)
    print(f'Legacy BIT STRING wrapper: {len(legacy_block)} bytes')
    print(f'Override block 0xA0: {len(insert_block)} bytes')

    new_blob = legacy_block + insert_block + recovered
    out_bytes = replace_cert2_blob(data, c_blob_off, c_off, c_hdr, new_blob)
    new_padded = roundup(len(new_blob), c_hdr.align_sz)
    print(f'New CERT2 dsize={len(new_blob)}  padded={new_padded}  align={c_hdr.align_sz}')
    return out_bytes


def cmd_install(args):
    path = Path(args.image)
    if not path.exists():
        print(f'[ERROR] file not found: {path}')
        return 2
    out_bytes = install_image(path.read_bytes())
    out = Path(args.out) if args.out else path.with_suffix(path.suffix + '.signed')
    out.write_bytes(out_bytes)
    print(f'[OK] written: {out}')
    return 0


def cmd_build(args):
    """One-shot pack + install: repack images into the template, then sign it
       in memory, writing a single ready-to-flash image."""
    src_dir = Path(args.dir)
    template = Path(args.template)
    out = Path(args.out) if args.out else template.with_suffix(template.suffix + '.signed')
    if not src_dir.is_dir():
        print(f'[ERROR] not a directory: {src_dir}')
        return 2
    if not template.exists():
        print(f'[ERROR] template not found: {template}')
        return 2
    packed = pack_image(src_dir, template)
    print()
    signed = install_image(packed)
    out.write_bytes(signed)
    print(f'[OK] written: {out} ({len(signed)} bytes)')
    return 0


def cmd_verify(args):
    path = Path(args.image)
    if not path.exists():
        print(f'[ERROR] file not found: {path}')
        return 2
    data = path.read_bytes()
    print(f"Image: {path.name}  Size: {len(data)} bytes")

    parts = parse_parts(data)
    if not parts:
        print('[ERROR] no part_hdr_t headers found')
        return 1
    cert2_entry, target_part = find_cert2_and_target(parts)
    if not cert2_entry:
        print('[ERROR] CERT2 partition header not found')
        return 1
    if not target_part:
        print('[ERROR] no target image partition found before CERT2')
        return 1

    _, c_off, c_blob_off, _, c_hdr = cert2_entry
    der = data[c_blob_off:c_blob_off + c_hdr.dsize]

    # Legacy layout: BIT STRING(wrapper) + 0xA0(override) + original DER
    first = find_first_tlv(der)
    if not first or not (first[0] == 0 and first[2] == 3):
        print(f'[FAIL] no legacy BIT STRING wrapper at start of CERT2 (off=0x{c_off:08x}) - fake cert not installed')
        return 1
    wrapper_size = first[4]

    after_bs = der[first[4]:]
    second = find_first_tlv(after_bs)
    if not second or not (second[0] == 2 and second[1] and second[2] == 0):
        print(f'[FAIL] legacy BIT STRING present ({wrapper_size} bytes) but no 0xA0 override block after it')
        return 1
    block_size = second[4]

    override_content = after_bs[second[3]:second[4]]
    inj_hdr_bit = find_oid_bitstring(override_content, OID_IMAGE_HEADER_HASH)
    inj_img_bit = find_oid_bitstring(override_content, OID_IMAGE_HASH)
    if inj_hdr_bit is None or inj_img_bit is None or len(inj_hdr_bit) < 1 or len(inj_img_bit) < 1:
        print(f'[FAIL] 0xA0 override block present ({block_size} bytes) but missing header/image hash OID')
        return 1

    inj_hdr = inj_hdr_bit[1:]
    inj_img = inj_img_bit[1:]
    alg = alg_from_len(len(inj_hdr))
    if alg is None:
        print(f'[FAIL] cannot identify injected hash algorithm (length {len(inj_hdr)})')
        return 1
    hfn = hashlib.sha256 if alg == 'sha256' else hashlib.sha384

    header_bytes, data_bytes = compute_hash_inputs(data, target_part)
    cur_hdr = hfn(header_bytes).digest()
    cur_img = hfn(data_bytes).digest()

    print(f'CERT2 off=0x{c_off:08x}  legacy layout detected')
    print(f'  BIT STRING wrapper: {wrapper_size} bytes')
    print(f'  0xA0 override block: {block_size} bytes')
    print(f'Algorithm: {alg}')
    print(f'  injected header hash: {inj_hdr.hex()}')
    print(f'  current  header hash: {cur_hdr.hex()}')
    print(f'  injected image  hash: {inj_img.hex()}')
    print(f'  current  image  hash: {cur_img.hex()}')

    hdr_ok = inj_hdr == cur_hdr
    img_ok = inj_img == cur_img
    if hdr_ok and img_ok:
        print('[OK] fake cert installed and hashes match current image content (valid)')
        return 0
    print('[WARN] fake cert installed but hashes do not match current image content (content changed, re-install needed)')
    if not hdr_ok:
        print('  - header hash mismatch')
    if not img_ok:
        print('  - image hash mismatch')
    return 1


def main():
    p = argparse.ArgumentParser(
        prog='core.py',
        description='MTK logo image toolchain: unpack / pack / install / build / verify',
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

    pi = sub.add_parser('install', help='inject legacy fake cert into an image')
    pi.add_argument('image', help='input image file')
    pi.add_argument('-o', '--out', help='output file (default <input>.signed)')
    pi.set_defaults(func=cmd_install)

    pb = sub.add_parser('build', help='pack + install in one step (ready-to-flash)')
    pb.add_argument('dir', help='directory of edited chunks (indexed by filename prefix)')
    pb.add_argument('template', help='original logo image as template')
    pb.add_argument('-o', '--out', help='output file (default <template>.signed)')
    pb.set_defaults(func=cmd_build)

    pv = sub.add_parser('verify', help='verify fake cert is successfully installed')
    pv.add_argument('image', help='input image file')
    pv.set_defaults(func=cmd_verify)

    args = p.parse_args()
    if args.version:
        print(f'core.py {VERSION}')
        return 0
    if not getattr(args, 'func', None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
