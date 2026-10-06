# cannon_logo_maker

MTK logo image toolchain for the Cannon device (MediaTek, legacy `bypass_mode=1` libsec).

This repo builds on the cert-bypass technique from
[pwnage24mtk](https://github.com/ELF-RC/pwnage24mtk) (CVE-2023-20696 /
CVE-2025-20730 family) and focuses it on a single device: editing the boot
logo (`logo.bin`) and getting the modified image to pass signature verification.

## Disclaimer

This project is for security research only. Make sure you have authorization
before using it. Not allowed for illegal use. It is not allowed to use this
exploit to provide paid services.

## How the bypass works

MTK boot images are MKIMG files (`part_hdr_t`, magic `0x58881688`). The `logo`
part data is a sequence of zlib-compressed BGRA pixel chunks preceded by an
offset table. Signature data lives in the `cert2` part as an ASN.1 DER blob
holding two OIDs:

- `2.16.886.2454.2.4`  Image Header Hash
- `2.16.886.2454.2.1`  Image Hash

In `bypass_mode=1` (old V5/V6 libsec, which the Cannon device uses), the ASN.1
parser steps into every object it meets. `install` prepends two sibling blocks
before the original CERT2 DER:

1. `BIT STRING(original CERT2 DER)` — the legacy wrapper libsec steps into
2. `0xA0 { OID + BIT STRING(new header hash), OID + BIT STRING(new image hash) }`

libsec finds the hash override first and trusts it, ignoring the real signed
content, so a modified image still passes verification.

## Scripts

| File | Scope | Subcommands |
|---|---|---|
| `resign.py` | CERT2 fake cert only | `install`, `verify` |
| `mklogo.py` | Logo image data only | `unpack`, `pack` |
| `core.py` | Unified single-file toolchain | `unpack`, `pack`, `install`, `build`, `verify` |

`core.py` merges both scripts into one module with a shared library; the two
specialized scripts remain for standalone use.

## Usage

Unified CLI: `-V` / `--version`, subcommands, `-o` / `--out`.

### Full workflow (edit boot logo)

```sh
# 1. unpack the original logo image
python3 core.py unpack logo.bin -o out/

# 2. edit PNGs in out/ (keep the filename's resolution; the leading
#    2-digit index selects the chunk, e.g. 00_1080x2340.png)

# 3. repack + sign in one step (ready to flash)
python3 core.py build out/ logo.bin -o logo.signed

# 4. verify before flashing
python3 core.py verify logo.signed
```

Or as separate steps:

```sh
python3 mklogo.py pack out/ logo.bin -o logo.packed
python3 resign.py install logo.packed -o logo.signed
```

### Sign an unmodified image

```sh
python3 resign.py install logo.bin -o logo.signed
python3 resign.py verify  logo.signed
```

`install` is idempotent: running it again strips the previous legacy prefix and
re-injects, yielding byte-identical output.

## File-name convention

`unpack` writes `{idx:02d}_{w}x{h}.png` for known sizes, or
`{idx:02d}_{bytes}.rgba` (raw BGRA) for unknown sizes. `pack` matches files by
the leading 2-digit index; any extension in the image whitelist is accepted
(png/jpg/jpeg/bmp/gif/tga/ppm/pgm/pbm/webp) plus `.rgba`. Chunks not present in
the directory are kept from the template verbatim.

Source images not matching a chunk's target size are center-cropped and/or
padded with opaque black — no scaling, so the pixel count always matches.

## SIZE_MAP

Decompressed size -> (width, height), 4 bytes per pixel (BGRA):

| Bytes | Resolution | Format |
|---|---|---|
| 10108800 | 1080x2340 | full-screen frame |
| 249200 | 178x350 | small image |
| 49444 | 263x47 | narrow strip |
| 36864 | 72x128 | icon |
| 14592 | 57x64 | small image |
| 11520 | 45x64 | small image |
| 2104 | 263x2 | thin strip |

## Dependencies

Pure Python standard library. PNG and BMP are decoded internally. Other formats
(JPG, GIF, TGA, PPM, WebP, ...) need [Pillow](https://python-pillow.org/)
(`pip install pillow`) or ImageMagick `convert`/`identify` on `PATH`.

## License

GPL-3.0, consistent with the upstream pwnage24mtk project.
