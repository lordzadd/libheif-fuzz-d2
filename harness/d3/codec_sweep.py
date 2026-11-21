#!/usr/bin/env python3
"""Header/bitstream disagreement sweep over genuine HEVC and AV1 files (D3, Campaign D).

Several advisories fixed upstream after the pin (GHSA-vv35-6hxg-95x8,
GHSA-86ch-j429-fpr2, GHSA-fpr5-xpfr-vcq3) share one wrong assumption: that the
image properties declared in the container (codec configuration box, 'ispe',
'pixi') describe the image the decoder will actually return. This script takes
files written by harness/d3/tools/gen_codec_images.cc (libheif's own encoder,
x265 and aom) and writes variants in which exactly one declared property
disagrees with the bitstream:

  hvcC  chroma_format_idc 0..3, bit_depth_luma 8..16, bit_depth_chroma 8..16
  av1C  seq_profile 0..2, high_bitdepth, twelve_bit, mono_chrome,
        subsampling_x, subsampling_y (each flipped)
  ispe  width/height x2, /2, +1, -1, 1
  pixi  every channel 8 / 10 / 12 / 16 bits; channel count 1 / 3 / 4

The edit is applied to every box of that type in the file (all tiles of a
grid, the alpha image too), so the file stays internally consistent apart from
the one disagreement. Output: <out>/matrix/<stem>__<mutation>-oXX with the
decode_matrix_fuzzer option byte XX in front.

  python3 harness/d3/codec_sweep.py --in /tmp/codec --out /tmp/codecsweep
"""

import argparse
import struct
from pathlib import Path

CONTAINERS = {b"meta": 4, b"iprp": 0, b"ipco": 0, b"moov": 0, b"trak": 0, b"mdia": 0,
              b"minf": 0, b"stbl": 0}
OPTION_BYTES = [0x00, 0x08]


def boxes(data, start=0, end=None):
    """Yield (type, payload_offset, payload_end) for every box, recursively."""
    end = len(data) if end is None else end
    pos = start
    while pos + 8 <= end:
        size, typ = struct.unpack(">I4s", data[pos:pos + 8])
        hdr = 8
        if size == 1:
            size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]
            hdr = 16
        elif size == 0:
            size = end - pos
        if size < hdr or pos + size > end:
            return
        yield typ, pos + hdr, pos + size
        if typ in CONTAINERS:
            yield from boxes(data, pos + hdr + CONTAINERS[typ], pos + size)
        pos += size


def mutate(data, typ, fn):
    """Apply fn(bytearray, payload_off, payload_end) to every box of type typ."""
    b = bytearray(data)
    hit = False
    for t, s, e in list(boxes(data)):
        if t == typ:
            fn(b, s, e)
            hit = True
    return bytes(b) if hit else None


def set_bits(b, off, mask, value):
    b[off] = (b[off] & ~mask & 0xFF) | (value & mask)


def mutations():
    m = []
    # hvcC: payload[16] chroma_format_idc (low 2 bits), [17] luma bd-8, [18] chroma bd-8 (low 3 bits)
    for v in range(4):
        m.append(("hvcC-chroma%d" % v, b"hvcC", lambda b, s, e, v=v: set_bits(b, s + 16, 0x03, v)))
    for v in range(9):
        m.append(("hvcC-lumabd%d" % (v + 8), b"hvcC", lambda b, s, e, v=v: set_bits(b, s + 17, 0x07, v)))
        m.append(("hvcC-chromabd%d" % (v + 8), b"hvcC", lambda b, s, e, v=v: set_bits(b, s + 18, 0x07, v)))
    # av1C: payload[1] seq_profile (top 3 bits); payload[2] bits: 0x40 high_bitdepth,
    # 0x20 twelve_bit, 0x10 mono_chrome, 0x08 subsampling_x, 0x04 subsampling_y
    for v in range(3):
        m.append(("av1C-profile%d" % v, b"av1C", lambda b, s, e, v=v: set_bits(b, s + 1, 0xE0, v << 5)))
    for name, bit in (("hbd", 0x40), ("12bit", 0x20), ("mono", 0x10), ("ssx", 0x08), ("ssy", 0x04)):
        m.append(("av1C-flip-" + name, b"av1C", lambda b, s, e, bit=bit: b.__setitem__(s + 2, b[s + 2] ^ bit)))

    # ispe (FullBox): payload[4:8] width, [8:12] height
    def ispe(fw, fh):
        def f(b, s, e):
            w, h = struct.unpack(">II", b[s + 4:s + 12])
            b[s + 4:s + 12] = struct.pack(">II", max(1, fw(w)), max(1, fh(h)))
        return f
    for name, fw, fh in (("w2x", lambda w: w * 2, lambda h: h), ("h2x", lambda w: w, lambda h: h * 2),
                         ("half", lambda w: w // 2, lambda h: h // 2), ("plus1", lambda w: w + 1, lambda h: h + 1),
                         ("minus1", lambda w: w - 1, lambda h: h - 1), ("one", lambda w: 1, lambda h: 1)):
        m.append(("ispe-" + name, b"ispe", ispe(fw, fh)))

    # pixi (FullBox): payload[4] num_channels, then one byte per channel
    def pixi_bits(v):
        def f(b, s, e):
            for i in range(s + 5, e):
                b[i] = v
        return f
    for v in (8, 10, 12, 16):
        m.append(("pixi-bits%d" % v, b"pixi", pixi_bits(v)))
    for n in (1, 3, 4):
        m.append(("pixi-n%d" % n, b"pixi", lambda b, s, e, n=n: b.__setitem__(s + 4, n)))
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out) / "matrix"
    out.mkdir(parents=True, exist_ok=True)
    muts = mutations()
    n = 0
    for f in sorted(Path(args.inp).glob("*.heif")):
        data = f.read_bytes()
        variants = [("orig", data)]
        for name, typ, fn in muts:
            v = mutate(data, typ, fn)
            if v is not None and v != data:
                variants.append((name, v))
        for name, v in variants:
            for ob in OPTION_BYTES:
                (out / ("%s__%s-o%02x" % (f.stem, name, ob))).write_bytes(bytes([ob]) + v)
                n += 1
    print("wrote %d matrix inputs to %s" % (n, out))


if __name__ == "__main__":
    main()
