#!/usr/bin/env python3
"""Systematic per-component bit-depth sweep over 'unci' images (D3, Campaign D).

Variant analysis of GHSA-r7gr-2xm2-23wf (fixed upstream after the pin): a
colour-conversion operator read several planes through one sample type chosen
from the first plane, so an image whose planes mix 8-bit and 16-bit storage was
read out of bounds. This script generates one small 'unci' file for every
combination of
  layout     mono, mono+alpha, RGB, RGB+alpha, YCbCr (4:4:4, 4:2:2, 4:2:0),
             YCbCr+alpha (4:4:4)
  bit depth  each component independently from --depths (default 8,10,12,16)
  size       --sizes (default 7x5 and 64x64: odd and even)
and writes each as <out>/<layout>-<depths>-<w>x<h>.heif plus, for
decode_matrix_fuzzer, one input per option byte in <out>/matrix/ (the option
byte selects ignore_transformations / convert_hdr_to_8bit / strict_decoding
and the alpha composition mode).

Every file is generated here from the ISO 23001-17 layout (gen_seeds.py box
writers); no upstream test input is used.

  python3 harness/d3/depth_sweep.py --out /tmp/sweep
  for f in /tmp/sweep/matrix/*; do build/fuzzing/decode_matrix_fuzzer "$f" -runs=1; done
"""

import argparse
import itertools
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_seeds as g  # noqa: E402

LAYOUTS = {
    "mono": ([g.CT_MONO], 0),
    "monoA": ([g.CT_MONO, g.CT_A], 0),
    "rgb": ([g.CT_R, g.CT_G, g.CT_B], 0),
    "rgbA": ([g.CT_R, g.CT_G, g.CT_B, g.CT_A], 0),
    "ycc444": ([g.CT_Y, g.CT_CB, g.CT_CR], 0),
    "ycc422": ([g.CT_Y, g.CT_CB, g.CT_CR], 1),
    "ycc420": ([g.CT_Y, g.CT_CB, g.CT_CR], 2),
}
OPTION_BYTES = [0x00, 0x02, 0x08, 0x0A, 0x10, 0x12]


def unc_spec_for(types, sampling, depths, w, h, fmts=None):
    fmts = fmts or [0] * len(types)
    return {"w": w, "h": h, "sampling": sampling, "interleave": 0, "block_size": 0,
            "flags": 0, "pixel_size": 0, "row_align": 0, "tile_align": 0, "tiles": (1, 1),
            "v1": None, "compress": None, "unit_type": 0, "icef": False,
            "size_mode": "exact", "pixi": False,
            "components": [{"type": t, "depth": d, "fmt": f, "align": 0}
                           for t, d, f in zip(types, depths, fmts)]}


def container(items, primary, refs=(), extra_props=None):
    """items: list of {"id","type","data","props","hidden"}; extra_props: boxes
    added to the primary item (transforms)."""
    ipco, assoc = [], []
    for it in items:
        props = list(it["props"]) + (list(extra_props) if (extra_props and it["id"] == primary) else [])
        idxs = []
        for p in props:
            if p in ipco:
                idx = ipco.index(p) + 1
            else:
                ipco.append(p)
                idx = len(ipco)
            idxs.append((idx, p[4:8] in (b"uncC", b"cmpd", b"irot", b"imir", b"clap")))
        assoc.append((it["id"], idxs))

    def meta(off):
        parts = g.hdlr() + g.pitm(primary) + g.iinf(items) + g.iloc(items, off)
        if refs:
            parts += g.iref(list(refs))
        return g.fullbox("meta", 0, 0, parts +
                         g.box("iprp", g.box("ipco", b"".join(ipco)) + g.ipma(assoc)))

    head = g.box("ftyp", b"mif1\0\0\0\0mif1miaf")
    pos = len(head) + len(meta({it["id"]: 0 for it in items})) + 8
    off, mdat = {}, b""
    for it in items:
        off[it["id"]] = pos + len(mdat)
        mdat += it["data"]
    return head + meta(off) + g.box("mdat", mdat)


def build(types, sampling, depths, w, h, fmts=None, transforms=(), grid=None):
    spec = unc_spec_for(types, sampling, depths, w, h, fmts)
    rng = random.Random(hash((tuple(depths), w, h)) & 0xFFFF)
    if grid is None:
        props, data = g.unc_props(spec, rng)
        items = [{"id": 1, "type": "unci", "data": data, "props": props, "hidden": False}]
        return container(items, 1, extra_props=transforms)
    rows, cols = grid
    items = [{"id": 1, "type": "grid", "data": g.grid_payload(rows, cols, w * cols, h * rows),
              "props": [g.ispe(w * cols, h * rows)], "hidden": False}]
    for i in range(rows * cols):
        props, data = g.unc_props(spec, rng)
        items.append({"id": 2 + i, "type": "unci", "data": data, "props": props, "hidden": True})
    return container(items, 1, refs=[("dimg", 1, [2 + i for i in range(rows * cols)])],
                     extra_props=transforms)


WIDE_KINDS = [  # (format, depth) pairs the byte-align unc decoder accepts
    (0, 32), (0, 64), (1, 32), (1, 64), (2, 64), (2, 128), (3, 16), (3, 32), (0, 8), (0, 16)]


def wide(out):
    """32/64/128-bit, signed, float and complex planes (bytealign decoder),
    crossed with transforms and grid composition."""
    xforms = {"none": [], "rot1": [g.irot(1)], "rot2": [g.irot(2)], "rot3": [g.irot(3)],
              "mirV": [g.imir(0)], "mirH": [g.imir(1)],
              "clap": [g.box("clap", __import__("struct").pack(">IIIIiIiI", 3, 1, 3, 1, 0, 1, 0, 1))],
              "rot1clap": [g.irot(1), g.box("clap", __import__("struct").pack(">IIIIiIiI", 3, 1, 3, 1, 0, 1, 0, 1))]}
    layouts = {"mono": [g.CT_MONO], "monoA": [g.CT_MONO, g.CT_A], "rgb": [g.CT_R, g.CT_G, g.CT_B],
               "rgbA": [g.CT_R, g.CT_G, g.CT_B, g.CT_A]}
    n = 0
    for lname, types in layouts.items():
        for (f1, d1), (f2, d2) in itertools.product(WIDE_KINDS, repeat=2):
            # colour components share kind 1; the last component (alpha, or B) gets kind 2
            fmts = [f1] * (len(types) - 1) + [f2]
            depths = [d1] * (len(types) - 1) + [d2]
            for xname, xf in xforms.items():
                for grid in (None, (2, 2)):
                    w, h = (6, 5)
                    data = build(types, 0, depths, w, h, fmts=fmts, transforms=xf, grid=grid)
                    stem = "wide-%s-f%dd%d-f%dd%d-%s-%s" % (lname, f1, d1, f2, d2, xname,
                                                             "grid" if grid else "single")
                    for ob in OPTION_BYTES:
                        (out / "matrix" / ("%s-o%02x" % (stem, ob))).write_bytes(bytes([ob]) + data)
                    n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--wide", action="store_true",
                    help="instead: wide/float/complex planes x transforms x grid")
    ap.add_argument("--depths", default="8,10,12,16")
    ap.add_argument("--sizes", default="7x5,64x64")
    args = ap.parse_args()
    depths = [int(d) for d in args.depths.split(",")]
    sizes = [tuple(int(v) for v in s.split("x")) for s in args.sizes.split(",")]
    out = Path(args.out)
    (out / "matrix").mkdir(parents=True, exist_ok=True)
    if args.wide:
        n = wide(out)
        print("wrote %d files, %d matrix inputs to %s" % (n, n * len(OPTION_BYTES), out))
        return
    n = 0
    for name, (types, sampling) in LAYOUTS.items():
        for combo in itertools.product(depths, repeat=len(types)):
            for w, h in sizes:
                data = build(types, sampling, list(combo), w, h)
                stem = "%s-%s-%dx%d" % (name, "_".join(map(str, combo)), w, h)
                (out / (stem + ".heif")).write_bytes(data)
                for ob in OPTION_BYTES:
                    (out / "matrix" / ("%s-o%02x" % (stem, ob))).write_bytes(bytes([ob]) + data)
                n += 1
    print("wrote %d files, %d matrix inputs to %s" % (n, n * len(OPTION_BYTES), out))


if __name__ == "__main__":
    main()
