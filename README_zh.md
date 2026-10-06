# cannon_logo_maker

Cannon 设备（联发科，legacy `bypass_mode=1` libsec）的 MTK logo 镜像工具链。

本项目基于 [pwnage24mtk](https://github.com/ELF-RC/pwnage24mtk)（CVE-2023-20696 /
CVE-2025-20730 系列）的证书绕过技术，聚焦于单一设备：编辑开机画面（`logo.bin`）并让修改后的镜像通过签名校验。

## 免责声明

本项目仅供安全研究使用。使用前请确保已获得授权。不得用于非法用途。不得利用此漏洞提供付费服务。

## 绕过原理

MTK 启动镜像是 MKIMG 格式（`part_hdr_t`，magic `0x58881688`）。`logo` 分区数据是一串 zlib 压缩的 BGRA 像素块，前面带偏移表。签名数据存放在 `cert2` 分区的 ASN.1 DER blob 里，包含两个 OID：

- `2.16.886.2454.2.4`  Image Header Hash（镜像头哈希）
- `2.16.886.2454.2.1`  Image Hash（镜像哈希）

在 `bypass_mode=1`（旧 V5/V6 libsec，Cannon 设备所用）下，ASN.1 解析器会进入它遇到的每个 object。`install` 在原始 CERT2 DER 前面追加两个同级块：

1. `BIT STRING(原始 CERT2 DER)` —— legacy 包装块，libsec 会钻进去
2. `0xA0 { OID + BIT STRING(新 header hash), OID + BIT STRING(新 image hash) }`

libsec 先碰到哈希覆盖块就信了，忽略后面真实签名内容，于是修改过的镜像也能通过校验。

## 脚本

| 文件 | 范围 | 子命令 |
|---|---|---|
| `resign.py` | 仅 CERT2 假证书 | `install`, `verify` |
| `mklogo.py` | 仅 logo 图像数据 | `unpack`, `pack` |
| `core.py` | 合并版单文件工具链 | `unpack`, `pack`, `install`, `build`, `verify` |

`core.py` 把两个脚本合并成一个带共享库的模块；两个专用脚本保留用于独立使用。

## 用法

统一 CLI：`-V` / `--version`、子命令、`-o` / `--out`。

### 完整流程（改开机画面）

```sh
# 1. 解包原始 logo 镜像
python3 core.py unpack logo.bin -o out/

# 2. 编辑 out/ 里的 PNG（保持文件名标注的分辨率；前导两位数字
#    索引选择对应块，如 00_1080x2340.png）

# 3. 一步打包 + 重签（可直接刷入）
python3 core.py build out/ logo.bin -o logo.signed

# 4. 刷入前验证
python3 core.py verify logo.signed
```

或分步执行：

```sh
python3 mklogo.py pack out/ logo.bin -o logo.packed
python3 resign.py install logo.packed -o logo.signed
```

### 给未修改的镜像重签

```sh
python3 resign.py install logo.bin -o logo.signed
python3 resign.py verify  logo.signed
```

`install` 是幂等的：重复执行会先剥离上一次的 legacy 前缀再重新注入，产出逐字节一致。

## 文件名约定

`unpack` 对已知尺寸输出 `{idx:02d}_{w}x{h}.png`，对未知尺寸输出
`{idx:02d}_{bytes}.rgba`（原始 BGRA）。`pack` 按前导两位数字索引匹配文件；
接受图片白名单扩展名（png/jpg/jpeg/bmp/gif/tga/ppm/pgm/pbm/webp）以及 `.rgba`。
目录里没有提供的块从模板原样保留。

源图尺寸不匹配块目标尺寸时，自动中心裁切和/或不透明黑边填充——不缩放，像素数始终匹配。

## SIZE_MAP

解压字节数 -> (宽, 高)，每像素 4 字节（BGRA）：

| 字节 | 分辨率 | 用途 |
|---|---|---|
| 10368000 | 1080x2400 | 全屏帧 |
| 10108800 | 1080x2340 | 全屏帧 |
| 249200 | 178x350 | 小图 |
| 49444 | 263x47 | 窄条 |
| 36864 | 72x128 | 图标 |
| 14592 | 57x64 | 小图 |
| 11520 | 45x64 | 小图 |
| 2104 | 263x2 | 细条 |

## 依赖

纯 Python 标准库。PNG 和 BMP 内置解码。其他格式（JPG、GIF、TGA、PPM、WebP……）需要
[Pillow](https://python-pillow.org/)（`pip install pillow`）或 PATH 里有
ImageMagick 的 `convert`/`identify`。

## 许可证

GPL-3.0，与上游 pwnage24mtk 项目一致。
