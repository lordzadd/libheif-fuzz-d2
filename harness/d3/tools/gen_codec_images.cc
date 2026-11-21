// Generate genuine HEVC and AV1 HEIF/AVIF files through libheif's public
// encoder API (x265 and aom). Used by harness/d3/codec_sweep.py, which then
// rewrites header fields so that the container disagrees with the bitstream.
//
//   gen_codec_images <outdir>
//
// For each codec, bit depth (8, 10, 12), chroma (420, 422, 444, monochrome),
// size (64x64, 33x17), alpha (no / yes) and layout (single image / 2x2 grid)
// one file <outdir>/<codec>-<bits>-<chroma>-<w>x<h>-<alpha>-<layout>.heif is
// written, if the encoder accepts the combination. Pixel content is a fixed
// gradient, so the output is deterministic for a given encoder version.

#include <libheif/heif.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static heif_image* make_image(int w, int h, int bits, heif_chroma chroma, bool alpha)
{
  heif_image* img = nullptr;
  heif_colorspace cs = (chroma == heif_chroma_monochrome) ? heif_colorspace_monochrome : heif_colorspace_YCbCr;
  if (heif_image_create(w, h, cs, chroma, &img).code) return nullptr;
  std::vector<heif_channel> chans = {heif_channel_Y};
  if (chroma != heif_chroma_monochrome) {
    chans.push_back(heif_channel_Cb);
    chans.push_back(heif_channel_Cr);
  }
  if (alpha) chans.push_back(heif_channel_Alpha);
  for (heif_channel c : chans) {
    int cw = w, ch = h;
    if ((c == heif_channel_Cb || c == heif_channel_Cr) && chroma != heif_chroma_444) {
      cw = (w + 1) / 2;
      if (chroma == heif_chroma_420) ch = (h + 1) / 2;
    }
    if (heif_image_add_plane(img, c, cw, ch, bits).code) {
      heif_image_release(img);
      return nullptr;
    }
    size_t stride;
    uint8_t* p = heif_image_get_plane2(img, c, &stride);
    int maxv = (1 << bits) - 1;
    for (int y = 0; y < ch; y++)
      for (int x = 0; x < cw; x++) {
        int v = ((x * 7 + y * 13 + int(c) * 31) * maxv / (cw * 7 + ch * 13 + 93)) & maxv;
        if (bits > 8) reinterpret_cast<uint16_t*>(p + y * stride)[x] = uint16_t(v);
        else p[y * stride + x] = uint8_t(v);
      }
  }
  return img;
}

int main(int argc, char** argv)
{
  if (argc < 2) {
    fprintf(stderr, "usage: %s outdir\n", argv[0]);
    return 1;
  }
  std::string out = argv[1];
  heif_init(nullptr);
  struct Codec { heif_compression_format fmt; const char* name; };
  const Codec codecs[] = {{heif_compression_HEVC, "hevc"}, {heif_compression_AV1, "av1"}};
  const int bitss[] = {8, 10, 12};
  struct Ch { heif_chroma c; const char* n; };
  const Ch chromas[] = {{heif_chroma_420, "420"}, {heif_chroma_422, "422"},
                        {heif_chroma_444, "444"}, {heif_chroma_monochrome, "mono"}};
  const int sizes[][2] = {{64, 64}, {33, 17}};
  int written = 0;
  for (const Codec& cd : codecs) {
    heif_encoder* enc = nullptr;
    for (int bits : bitss)
      for (const Ch& ch : chromas)
        for (auto& sz : sizes)
          for (int alpha = 0; alpha < 2; alpha++)
            for (int grid = 0; grid < 2; grid++) {
              heif_context* ctx = heif_context_alloc();
              if (heif_context_get_encoder_for_format(ctx, cd.fmt, &enc).code) {
                heif_context_free(ctx);
                continue;
              }
              heif_encoder_set_lossy_quality(enc, 60);
              heif_encoder_set_parameter(enc, "chroma", ch.n);
              heif_image* img = make_image(sz[0], sz[1], bits, ch.c, alpha);
              heif_error err{heif_error_Usage_error};
              if (img) {
                if (!grid) {
                  err = heif_context_encode_image(ctx, img, enc, nullptr, nullptr);
                }
                else {
                  heif_image* tiles[4] = {img, img, img, img};
                  heif_image_handle* gh = nullptr;
                  err = heif_context_encode_grid(ctx, tiles, 2, 2, enc, nullptr, &gh);
                  if (!err.code && gh) heif_image_handle_release(gh);
                }
              }
              if (!err.code) {
                char name[256];
                snprintf(name, sizeof(name), "%s/%s-%d-%s-%dx%d-%s-%s.heif", out.c_str(), cd.name,
                         bits, ch.n, sz[0], sz[1], alpha ? "alpha" : "noalpha", grid ? "grid" : "single");
                if (!heif_context_write_to_file(ctx, name).code) written++;
              }
              if (img) heif_image_release(img);
              heif_encoder_release(enc);
              heif_context_free(ctx);
            }
  }
  printf("wrote %d files\n", written);
  heif_deinit();
  return 0;
}
