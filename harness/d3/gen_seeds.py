#!/usr/bin/env python3
"""Generate structurally valid HEIF container skeletons as fuzzing seeds (D3).

prepare_corpus.py only carves boxes out of the upstream fixtures, so mutations
spend most of their budget repairing a broken container. This generator writes
complete files instead: ftyp + meta (hdlr, pitm, iinf, iloc, iprp/ipco/ipma,
iref) + mdat, with every offset correct, so a single mutation already lands
inside a parseable item table.

The image items are ISO/IEC 23001-17 uncompressed items ('unci'), because they
decode without an external codec and therefore reach the pixel paths
(unc decoders, grid/overlay/iden composition, transforms, colour conversion) on
every execution. The randomised dimensions are:

  * uncC v0 component list (type, bit depth 1..16, format, align size),
    sampling mode, interleave mode, block size, flags, pixel size,
    row/tile align, tile columns/rows; or uncC v1 with a profile
  * cmpd component types (mono, Y, Cb, Cr, R, G, B, alpha, filter array, ...)
  * optional cmpC (zlib/defl/brot) with optional icef unit table
  * ispe, pixi, irot, imir, clap, colr nclx
  * composition: single item, grid of N tiles whose tiles may *differ* in bit
    depth, component set and sampling, overlay, iden chain, thumbnail/auxl
    references
  * payload: exact expected size, truncated, or padded

Everything is generated from a fixed RNG seed, so the output is reproducible:

  python3 harness/d3/gen_seeds.py --count 400 --seed 428

Seeds are written to corpora/seed/<target>/gen-<sha1> for file_fuzzer,
api_fuzzer and tile_fuzzer (the three targets that take a whole file), and a
manifest is written to results/<run>/gen_seed_manifest.csv. No upstream test
input is used or transformed.
"""

import argparse
import csv
import hashlib
import random
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "corpora" / "seed"
TARGETS = ["file_fuzzer", "api_fuzzer", "tile_fuzzer"]


# ------------------------------------------------------------------ boxes
def box(t, payload):
    return struct.pack(">I", 8 + len(payload)) + t.encode() + payload


def fullbox(t, version, flags, payload):
    return box(t, struct.pack(">I", (version << 24) | flags) + payload)


def ftyp(rng):
    major = rng.choice([b"mif1", b"heic", b"avif", b"unif"])
    compat = [b"mif1", b"miaf", b"unif"]
    rng.shuffle(compat)
    return box("ftyp", major + b"\0\0\0\0" + b"".join(compat))


def hdlr():
    return fullbox("hdlr", 0, 0, b"\0\0\0\0" + b"pict" + b"\0" * 12 + b"\0")


def pitm(item_id):
    return fullbox("pitm", 0, 0, struct.pack(">H", item_id))


def infe(item_id, item_type, hidden=False):
    return fullbox("infe", 2, 1 if hidden else 0,
                   struct.pack(">HH", item_id, 0) + item_type.encode() + b"\0")


def iinf(items):
    return fullbox("iinf", 0, 0, struct.pack(">H", len(items)) +
                   b"".join(i["infe"] if "infe" in i else infe(i["id"], i["type"], i.get("hidden", False))
                            for i in items))


def mime_infe(item_id, content_type, encoding):
    body = struct.pack(">HH", item_id, 0) + b"mime" + b"\0" + content_type.encode() + b"\0"
    if encoding is not None:
        body += encoding.encode() + b"\0"
    return fullbox("infe", 2, 0, body)


# ------------------------------------------------- regions and metadata
# Enabled with --features regions,meta. Campaign B never parsed a region item
# (region.cc: 0 of 441 lines, docs/D3.md "Code the harness never reached") and
# never decompressed a metadata item.
def rgan_payload(rng, ref_w, ref_h):
    wide = rng.random() < 0.3
    fs = 4 if wide else 2
    sfmt, ufmt = (">i", ">I") if wide else (">h", ">H")
    smax = (1 << 31) - 1 if wide else (1 << 15) - 1
    umax = (1 << 32) - 1 if wide else (1 << 16) - 1

    def s(v):
        return struct.pack(sfmt, max(-smax - 1, min(smax, v)))

    def u(v):
        return struct.pack(ufmt, max(0, min(umax, v)))

    body = struct.pack(">BB", 0, 1 if wide else 0) + u(ref_w) + u(ref_h)
    n = rng.choice([1, 1, 2, 3, 5])
    body += struct.pack(">B", n)
    for _ in range(n):
        g = rng.choice([0, 1, 2, 3, 4, 5, 6, 5, 3, 7])
        body += struct.pack(">B", g)
        x, y = rng.randint(-4, ref_w + 4), rng.randint(-4, ref_h + 4)
        if g == 0:
            body += s(x) + s(y)
        elif g in (1, 2, 4):
            body += s(x) + s(y) + u(rng.randint(0, ref_w + 2)) + u(rng.randint(0, ref_h + 2))
        elif g in (3, 6):
            npts = rng.choice([0, 1, 2, 3, 4, 7, 16])
            body += u(npts)
            for _ in range(npts):
                body += s(rng.randint(-8, ref_w + 8)) + s(rng.randint(-8, ref_h + 8))
        elif g == 5:
            mw, mh = rng.choice([1, 3, 8, 9, 16]), rng.choice([1, 2, 7, 8])
            body += s(x) + s(y) + u(mw) + u(mh)
            body += struct.pack(">B", rng.choice([0, 0, 0, 1]))
            nbytes = (mw * mh + 7) // 8 - rng.choice([0, 0, 0, 1])
            body += bytes(rng.getrandbits(8) for _ in range(max(0, nbytes)))
        # g == 7: unknown geometry type, parser skips it
    return body


def xmp_payload(rng):
    xml = (b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf='
           b'"http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta>')
    return xml * rng.choice([1, 2, 8])


def exif_payload(rng):
    tiff = b"MM\0*" + struct.pack(">I", 8) + struct.pack(">H", 1) + \
        struct.pack(">HHII", 0x0112, 3, 1, rng.randint(1, 8) << 16) + b"\0\0\0\0"
    off = rng.choice([0, 0, 6, 100, 0xFFFFFFFF])
    pad = b"Exif\0\0" if off == 6 else b""
    return struct.pack(">I", off) + pad + tiff


def iloc(items, offsets):
    # version 0, offset_size 4, length_size 4, base_offset_size 0
    body = struct.pack(">BBH", 0x44, 0x00, len(items))
    for it in items:
        body += struct.pack(">HHHII", it["id"], 0, 1, offsets[it["id"]], len(it["data"]))
    return fullbox("iloc", 0, 0, body)


def ipma(assoc):
    body = struct.pack(">I", len(assoc))
    for item_id, idxs in assoc:
        body += struct.pack(">HB", item_id, len(idxs))
        for idx, essential in idxs:
            body += struct.pack(">B", (0x80 if essential else 0) | idx)
    return fullbox("ipma", 0, 0, body)


def iref(refs):
    body = b""
    for kind, src, dsts in refs:
        body += box(kind, struct.pack(">HH", src, len(dsts)) +
                    b"".join(struct.pack(">H", d) for d in dsts))
    return fullbox("iref", 0, 0, body)


def ispe(w, h):
    return fullbox("ispe", 0, 0, struct.pack(">II", w, h))


def pixi(bits):
    return fullbox("pixi", 0, 0, struct.pack(">B", len(bits)) + bytes(bits))


def irot(a):
    return box("irot", struct.pack(">B", a & 3))


def imir(axis):
    return box("imir", struct.pack(">B", axis & 1))


def clap(rng, w, h):
    vals = []
    for full in (w, h):
        n = rng.randint(1, max(1, full))
        vals += [n, 1]
    vals += [rng.randint(-4, 4), rng.choice([1, 2]), rng.randint(-4, 4), rng.choice([1, 2])]
    return box("clap", struct.pack(">IIIIiIiI", *vals))


def colr_nclx(rng):
    return box("colr", b"nclx" + struct.pack(">HHHB", rng.choice([1, 2, 9]),
                                              rng.choice([1, 2, 13, 16]),
                                              rng.choice([0, 1, 5, 6, 9]),
                                              rng.choice([0x00, 0x80])))


# ----------------------------------------------------------- unc items
# ISO 23001-17 component types used by libheif.
CT_MONO, CT_Y, CT_CB, CT_CR, CT_R, CT_G, CT_B, CT_A = 0, 1, 2, 3, 4, 5, 6, 7
CT_DEPTH, CT_DISP, CT_PAL, CT_FA, CT_PAD = 8, 9, 10, 11, 12

LAYOUTS = [
    ([CT_MONO], [0]),
    ([CT_Y], [0]),
    ([CT_R, CT_G, CT_B], [0]),
    ([CT_R, CT_G, CT_B, CT_A], [0]),
    ([CT_Y, CT_CB, CT_CR], [0, 1, 2, 3]),
    ([CT_Y, CT_CB, CT_CR, CT_A], [0, 1, 2]),
    ([CT_MONO, CT_A], [0]),
    ([CT_FA], [0]),
    ([CT_R, CT_G, CT_B, CT_PAD], [0]),
    ([CT_DEPTH], [0]),
]

V1_PROFILES = [b"rgb3", b"rgba", b"abgr", b"2vuy", b"yuv2", b"v308", b"v408",
               b"i420", b"nv12", b"nv21", b"yu22", b"yv22", b"yv20", b"y210",
               b"v410", b"v210", b"yvyu", b"vyuy", b"yuv1"]


def unc_spec(rng, base=None):
    """A random uncompressed-image description. `base`, if given, is a tile
    spec from the same grid: most fields are kept so the grid is consistent,
    and a few are perturbed on purpose (bit depth, sampling, components)."""
    if base is not None:
        spec = dict(base)
        spec["components"] = [dict(c) for c in base["components"]]
        r = rng.random()
        if r < 0.7:
            return spec          # consistent tile: the grid decodes fully
        r = rng.random()
        if r < 0.35:
            for c in spec["components"]:
                c["depth"] = rng.choice([1, 4, 8, 10, 12, 16])
        elif r < 0.55:
            spec["sampling"] = rng.choice([0, 1, 2, 3])
        elif r < 0.7:
            spec = None
        elif r < 0.85:
            spec["w"] = max(1, spec["w"] + rng.choice([-1, 1, 3]))
            spec["h"] = max(1, spec["h"] + rng.choice([-1, 1, 3]))
        if spec is not None:
            return spec
    if rng.random() < 0.75:
        return valid_unc_spec(rng)
    types, samplings = rng.choice(LAYOUTS)
    depth = rng.choice([8, 8, 8, 1, 2, 4, 5, 10, 12, 14, 16, 3, 7])
    fmt = 0
    if rng.random() < 0.12:
        fmt = rng.choice([1, 2, 3])
        depth = rng.choice([16, 32, 64]) if fmt != 2 else rng.choice([32, 64])
        depth = min(depth, 256)
    comps = []
    for t in types:
        d = depth if rng.random() < 0.85 else rng.choice([1, 8, 10, 16])
        align = 0
        if rng.random() < 0.25:
            align = rng.choice([1, 2, 4, 8])
            if align * 8 < d:
                align = 0
        comps.append({"type": t, "depth": d, "fmt": fmt, "align": align})
    interleave = rng.choice([0, 0, 1, 1, 2, 3, 4, 5])
    sampling = rng.choice(samplings)
    if interleave == 2 and types[:3] != [CT_Y, CT_CB, CT_CR]:
        interleave = 0
    tiles = (1, 1)
    if rng.random() < 0.3:
        tiles = (rng.choice([1, 2, 3, 4]), rng.choice([1, 2, 3]))
    w = rng.choice([1, 2, 3, 4, 7, 8, 13, 16, 17, 31, 32, 64])
    h = rng.choice([1, 2, 3, 4, 5, 8, 9, 16, 33, 64])
    w = max(w, tiles[0])
    h = max(h, tiles[1])
    return {
        "w": w, "h": h, "components": comps, "sampling": sampling,
        "interleave": interleave,
        "block_size": rng.choice([0, 0, 0, 1, 2, 3, 4, 8]),
        "flags": rng.choice([0, 0, 0, 0x80, 0x40, 0x20, 0x10, 0x08, 0xF8]),
        "pixel_size": rng.choice([0, 0, 0, 1, 3, 4, 6, 8]),
        "row_align": rng.choice([0, 0, 0, 1, 2, 4, 8, 3]),
        "tile_align": rng.choice([0, 0, 0, 4, 16]),
        "tiles": tiles,
        "v1": V1_PROFILES[rng.randrange(len(V1_PROFILES))] if rng.random() < 0.12 else None,
        "compress": rng.choice([None] * 6 + ["zlib", "defl", "brot"]),
        "unit_type": rng.choice([0, 1, 2, 3, 4]),
        "icef": rng.random() < 0.5,
        "size_mode": rng.choice(["exact"] * 6 + ["short", "long", "zero"]),
        "pixi": rng.random() < 0.5,
    }


def valid_unc_spec(rng):
    """A spec that one of the seven unc decoder families accepts
    (unc_decoder.cc get_unc_decoder / can_decode), so the seed reaches the
    tile decode loop and the pixel paths behind it."""
    family = rng.choice(["component", "component", "pixel", "pixel", "row", "mixed",
                         "tile_component", "bytealign", "block_component", "block_pixel"])
    types, samplings = rng.choice(LAYOUTS[:7])
    sampling = 0
    if family in ("component", "tile_component") and types[:3] == [CT_Y, CT_CB, CT_CR]:
        sampling = rng.choice([0, 1, 2])
    if family == "mixed":
        types = rng.choice([[CT_Y, CT_CB, CT_CR], [CT_Y, CT_CB, CT_CR, CT_A]])
        sampling = rng.choice([1, 2])
    depth = rng.choice([8, 8, 8, 1, 2, 4, 5, 10, 12, 16])
    fmt, align, block_size, pixel_size, flags = 0, 0, 0, 0, rng.choice([0, 0, 0x80, 0x08])
    interleave = {"component": 0, "tile_component": 4, "pixel": 1, "row": 3, "mixed": 2,
                  "bytealign": 0, "block_component": 0, "block_pixel": 1}[family]
    depths = [depth] * len(types)
    if family == "bytealign":
        sampling = 0
        fmt = rng.choice([0, 0, 1, 2, 3])
        d = {0: rng.choice([8, 16, 32, 64]), 1: rng.choice([32, 64]),
             2: rng.choice([64, 128]), 3: rng.choice([8, 16, 32])}[fmt]
        depths = [d] * len(types)
        flags = rng.choice([0, 0x80])
    elif family == "block_component":
        sampling = 0
        block_size = rng.choice([1, 2, 3])  # depth must be in (bits/2, min(16, bits)]
        bits = block_size * 8
        depths = [rng.randint(bits // 2 + 1, min(16, bits))] * len(types)
        flags = rng.choice([0, 0x40, 0x20, 0x10, 0x60])
    elif family == "block_pixel":
        sampling = 0
        pixel_size = rng.choice([1, 2, 3, 4, 6, 8])
        per = max(1, min(16, pixel_size * 8 // len(types)))
        depths = [rng.randint(1, per)] * len(types)
        block_size = rng.choice([0, pixel_size])
        flags = rng.choice([0, 0x40, 0x20, 0x10])
    elif family == "pixel":
        flags = rng.choice([0, 0x08])
        if rng.random() < 0.4:
            pixel_size = (sum(depths) + 7) // 8 + rng.choice([0, 1, 2])
    else:
        align = rng.choice([0, 0, 1, 2]) if depth <= 8 else rng.choice([0, 2])
    if family in ("row", "mixed") and flags & 0x80 and max(depths) > 8:
        flags = 0
    comps = [{"type": t, "depth": d, "fmt": fmt, "align": align} for t, d in zip(types, depths)]
    tiles = (1, 1)
    tw, th = rng.choice([1, 2, 4, 8, 16]), rng.choice([1, 2, 3, 8, 16])
    if rng.random() < 0.35:
        tiles = (rng.choice([1, 2, 3, 4]), rng.choice([1, 2, 3]))
    if sampling in (1, 2):
        tw += tw % 2
    if sampling == 2:
        th += th % 2
    row_align = 0
    if family not in ("block_component", "block_pixel") and rng.random() < 0.25:
        row_align = rng.choice([2, 4, 8])
    tile_align = rng.choice([0, 0, 0, 4, 8])
    return {
        "w": tw * tiles[0], "h": th * tiles[1], "components": comps, "sampling": sampling,
        "interleave": interleave, "block_size": block_size, "flags": flags,
        "pixel_size": pixel_size, "row_align": row_align, "tile_align": tile_align,
        "tiles": tiles, "v1": None,
        "compress": rng.choice([None] * 8 + ["zlib", "defl", "brot"]),
        "unit_type": rng.choice([0, 1, 2]),
        "icef": rng.random() < 0.5,
        "size_mode": rng.choice(["exact"] * 8 + ["short", "long"]),
        "pixi": rng.random() < 0.5,
    }


def sub_wh(w, h, sampling, ctype):
    if ctype in (CT_CB, CT_CR):
        if sampling == 1:
            return (w + 1) // 2, h
        if sampling == 2:
            return (w + 1) // 2, (h + 1) // 2
        if sampling == 3:
            return (w + 3) // 4, h
    return w, h


def expected_bytes(spec):
    """Upper bound on the payload the decoder reads: per-sample bytes (with
    align/block/pixel size), row and tile alignment padding for every tile.
    A payload larger than needed is accepted, so 'exact' seeds decode."""
    tx, ty = spec["tiles"]
    total = 0
    for c in spec["components"]:
        cw, ch = sub_wh(spec["w"], spec["h"], spec["sampling"], c["type"])
        bpc = max(c["align"], (c["depth"] + 7) // 8, spec["block_size"])
        total += cw * ch * bpc
        total += spec["row_align"] * ch * tx
    if spec["pixel_size"]:
        total = max(total, spec["w"] * spec["h"] * spec["pixel_size"] + spec["row_align"] * spec["h"] * tx)
    total += spec["tile_align"] * tx * ty
    return max(total, 1)


def unc_props(spec, rng):
    """Return (property boxes, payload) for one unci item."""
    comps = spec["components"]
    props = [ispe(spec["w"], spec["h"])]
    props.append(box("cmpd", struct.pack(">I", len(comps)) +
                     b"".join(struct.pack(">H", c["type"]) for c in comps)))
    if spec["v1"]:
        props.append(fullbox("uncC", 1, 0, spec["v1"]))
    else:
        body = struct.pack(">II", 0, len(comps))
        for i, c in enumerate(comps):
            body += struct.pack(">HBBB", i, (c["depth"] - 1) & 0xFF, c["fmt"], c["align"])
        body += struct.pack(">BBBB", spec["sampling"], spec["interleave"],
                            spec["block_size"], spec["flags"])
        body += struct.pack(">IIIII", spec["pixel_size"], spec["row_align"],
                            spec["tile_align"], spec["tiles"][0] - 1, spec["tiles"][1] - 1)
        props.append(fullbox("uncC", 0, 0, body))
    if spec["pixi"]:
        props.append(pixi([min(255, c["depth"]) for c in comps]))

    n = expected_bytes(spec)
    mode = spec["size_mode"]
    if mode == "short":
        n = max(0, n - rng.randint(1, max(1, n // 2)))
    elif mode == "long":
        n += rng.randint(1, 64)
    elif mode == "zero":
        n = 0
    raw = bytes(rng.getrandbits(8) for _ in range(min(n, 1 << 15)))

    if spec["compress"]:
        if spec["compress"] == "zlib":
            data = zlib.compress(raw)
        elif spec["compress"] == "defl":
            co = zlib.compressobj(wbits=-15)
            data = co.compress(raw) + co.flush()
        else:
            # No brotli encoder in the stdlib: store the raw bytes; the decoder
            # then exercises its error path with a valid table layout.
            data = raw
        props.append(fullbox("cmpC", 0, 0, spec["compress"].encode() +
                             struct.pack(">B", spec["unit_type"])))
        if spec["icef"]:
            # one unit covering everything, 32-bit offset and size
            codes = (2 << 5) | (2 << 2)
            props.append(fullbox("icef", 0, 0, struct.pack(">BIII", codes, 1, 0, len(data))))
        raw = data
    return props, raw


# ------------------------------------------------------------- files
def grid_payload(rows, cols, w, h):
    if w > 0xFFFF or h > 0xFFFF:
        return struct.pack(">BBBBII", 0, 1, rows - 1, cols - 1, w, h)
    return struct.pack(">BBBBHH", 0, 0, rows - 1, cols - 1, w, h)


def overlay_payload(rng, n, w, h):
    body = struct.pack(">BB", 0, 0) + struct.pack(">HHHH", *[rng.randrange(65536) for _ in range(4)])
    body += struct.pack(">HH", w, h)
    for _ in range(n):
        body += struct.pack(">hh", rng.randint(-8, w), rng.randint(-8, h))
    return body


def build_file(rng, features=("unc",)):
    items = []          # {"id", "type", "data", "props": [box], "hidden"}
    refs = []
    kind = rng.choice(["single"] * 3 + ["grid"] * 4 + ["overlay"] * 2 + ["iden", "thumb"])
    next_id = [1]

    def new_id():
        v = next_id[0]
        next_id[0] += 1
        return v

    def add_unc(spec, hidden=False):
        props, data = unc_props(spec, rng)
        it = {"id": new_id(), "type": "unci", "data": data, "props": props, "hidden": hidden}
        items.append(it)
        return it

    primary = None
    if kind in ("single", "thumb"):
        spec = unc_spec(rng)
        primary = add_unc(spec)
        if kind == "thumb":
            t = add_unc(unc_spec(rng))
            refs.append(("thmb", t["id"], [primary["id"]]))
    elif kind == "grid":
        rows, cols = rng.choice([(1, 2), (2, 1), (2, 2), (1, 3), (3, 2), (2, 3)])
        base = unc_spec(rng)
        base["tiles"] = (1, 1)
        gid = new_id()
        tiles = [add_unc(unc_spec(rng, base), hidden=True) for _ in range(rows * cols)]
        gw = base["w"] * cols - rng.choice([0, 0, 0, 1, base["w"] // 2])
        gh = base["h"] * rows - rng.choice([0, 0, 0, 1, base["h"] // 2])
        gw, gh = max(1, gw), max(1, gh)
        if rng.random() < 0.15:
            gw += rng.choice([1, base["w"], 100])
        primary = {"id": gid, "type": "grid", "data": grid_payload(rows, cols, gw, gh),
                   "props": [ispe(gw, gh)], "hidden": False}
        items.insert(0, primary)
        dsts = [t["id"] for t in tiles]
        if rng.random() < 0.15:
            dsts = dsts[:-1]
        if rng.random() < 0.1:
            dsts[0] = gid
        refs.append(("dimg", gid, dsts))
    elif kind == "overlay":
        n = rng.choice([1, 2, 3])
        oid = new_id()
        kids = [add_unc(unc_spec(rng), hidden=True) for _ in range(n)]
        ow, oh = rng.choice([1, 8, 16, 33, 64]), rng.choice([1, 8, 16, 33, 64])
        primary = {"id": oid, "type": "iovl", "data": overlay_payload(rng, n, ow, oh),
                   "props": [ispe(ow, oh)], "hidden": False}
        items.insert(0, primary)
        refs.append(("dimg", oid, [k["id"] for k in kids]))
    elif kind == "iden":
        iid = new_id()
        src = add_unc(unc_spec(rng), hidden=True)
        primary = {"id": iid, "type": "iden", "data": b"", "props": [ispe(src_w(src), src_h(src))],
                   "hidden": False}
        items.insert(0, primary)
        refs.append(("dimg", iid, [src["id"]]))

    # transforms on the primary
    if rng.random() < 0.35:
        primary["props"].append(irot(rng.randrange(4)))
    if rng.random() < 0.2:
        primary["props"].append(imir(rng.randrange(2)))
    if rng.random() < 0.2:
        w, h = src_w(primary), src_h(primary)
        primary["props"].append(clap(rng, w, h))
    if rng.random() < 0.3:
        primary["props"].append(colr_nclx(rng))
    if rng.random() < 0.15:
        aux = add_unc(unc_spec(rng), hidden=True)
        aux["props"].append(fullbox("auxC", 0, 0, b"urn:mpeg:mpegB:cicp:systems:auxiliary:alpha\0"))
        refs.append(("auxl", aux["id"], [primary["id"]]))

    # Optional feature blocks. Each consumes random numbers only when enabled,
    # so the default feature set reproduces the long2a seeds byte for byte.
    if "regions" in features and rng.random() < 0.6:
        for _ in range(rng.choice([1, 1, 2])):
            rid = new_id()
            items.append({"id": rid, "type": "rgan", "props": [], "hidden": False,
                          "data": rgan_payload(rng, src_w(primary), src_h(primary))})
            refs.append(("cdsc", rid, [primary["id"]]))
            if rng.random() < 0.4:
                mspec = valid_unc_spec(rng)
                mspec["components"] = [{"type": CT_MONO, "depth": 8, "fmt": 0, "align": 0}]
                mspec["interleave"], mspec["sampling"], mspec["block_size"] = 0, 0, 0
                mspec["pixel_size"], mspec["flags"], mspec["compress"] = 0, 0, None
                m = add_unc(mspec, hidden=True)
                refs.append(("mask", rid, [m["id"]]))
    if "meta" in features and rng.random() < 0.6:
        enc = rng.choice([None, "identity", "compress_zlib", "deflate", "br", "gzip"])
        raw = xmp_payload(rng)
        if enc == "compress_zlib":
            data = zlib.compress(raw)
        elif enc == "deflate":
            co = zlib.compressobj(wbits=-15)
            data = co.compress(raw) + co.flush()
        elif enc in ("br", "gzip"):
            data = raw          # not valid for the encoding: decoder error path
        else:
            data = raw
        if rng.random() < 0.15:
            data = data[: len(data) // 2]
        mid = new_id()
        items.append({"id": mid, "type": "mime", "props": [], "hidden": False, "data": data,
                      "infe": mime_infe(mid, "application/rdf+xml", enc)})
        refs.append(("cdsc", mid, [primary["id"]]))
        if rng.random() < 0.5:
            eid = new_id()
            items.append({"id": eid, "type": "Exif", "props": [], "hidden": False,
                          "data": exif_payload(rng)})
            refs.append(("cdsc", eid, [primary["id"]]))

    # property table: de-duplicate identical boxes like real writers do
    ipco_boxes, assoc = [], []
    for it in items:
        idxs = []
        for p in it["props"]:
            if p in ipco_boxes:
                idx = ipco_boxes.index(p) + 1
            else:
                ipco_boxes.append(p)
                idx = len(ipco_boxes)
            idxs.append((idx, p[4:8] in (b"uncC", b"cmpd", b"cmpC", b"icef", b"irot", b"imir", b"clap")))
        assoc.append((it["id"], idxs[:127]))
    items_sorted = sorted(items, key=lambda i: i["id"])

    def meta_box(offsets):
        parts = [hdlr(), pitm(primary["id"]), iinf(items_sorted), iloc(items_sorted, offsets)]
        if refs:
            parts.append(iref(refs))
        parts.append(box("iprp", box("ipco", b"".join(ipco_boxes)) + ipma(assoc)))
        return fullbox("meta", 0, 0, b"".join(parts))

    head = ftyp(rng)
    dummy = {it["id"]: 0 for it in items_sorted}
    meta_len = len(meta_box(dummy))
    pos = len(head) + meta_len + 8
    offsets = {}
    mdat = b""
    for it in items_sorted:
        offsets[it["id"]] = pos + len(mdat)
        mdat += it["data"]
    out = head + meta_box(offsets) + box("mdat", mdat)
    return out, kind


def src_w(it):
    for p in it["props"]:
        if p[4:8] == b"ispe":
            return struct.unpack(">I", p[12:16])[0]
    return 1


def src_h(it):
    for p in it["props"]:
        if p[4:8] == b"ispe":
            return struct.unpack(">I", p[16:20])[0]
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=400)
    ap.add_argument("--seed", type=int, default=428)
    ap.add_argument("--max-bytes", type=int, default=65536)
    ap.add_argument("--manifest", default=str(ROOT / "results" / "long2a" / "gen_seed_manifest.csv"))
    ap.add_argument("--features", default="unc",
                    help="comma list: unc (always), regions, meta. "
                         "long2a used the default; long2b added regions,meta")
    ap.add_argument("--seed-root", default=str(SEED),
                    help="output root; files go to <root>/<target>/gen-<sha1>")
    args = ap.parse_args()
    seed_root = Path(args.seed_root)
    features = tuple(f.strip() for f in args.features.split(","))
    rng = random.Random(args.seed)
    rows = []
    seen = set()
    made = 0
    while made < args.count:
        data, kind = build_file(rng, features)
        if len(data) > args.max_bytes:
            continue
        digest = hashlib.sha1(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        made += 1
        for t in TARGETS:
            d = seed_root / t
            d.mkdir(parents=True, exist_ok=True)
            (d / ("gen-" + digest)).write_bytes(data)
            rows.append({"fuzzer": t, "sha1": digest, "bytes": len(data),
                         "origin": "gen_seeds.py:seed=%d:features=%s:kind=%s"
                                   % (args.seed, "+".join(features), kind)})
    m = Path(args.manifest)
    m.parent.mkdir(parents=True, exist_ok=True)
    with open(m, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["fuzzer", "sha1", "bytes", "origin"])
        w.writeheader()
        w.writerows(rows)
    print("wrote %d files x %d targets; manifest %s" % (made, len(TARGETS), m))


if __name__ == "__main__":
    main()
