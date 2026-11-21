// decode_matrix_fuzzer: decode the primary image (and every top-level image)
// of a HEIF file into every output colorspace/chroma combination that the
// public API offers, the way a real application chooses an output format.
//
// The upstream targets always decode to YCbCr 4:2:0 (file/tile/sequence/api)
// or monochrome (depth images), so the colour-conversion planner never builds
// the RGB, interleaved, HDR and alpha-compositing paths from file input. This
// target is the only change to the harness; the library is unchanged. It is
// built by scripts/build_d3_extra.sh against the same instrumented libheif.
//
// The first input byte selects decoding options (ignore_transformations,
// convert_hdr_to_8bit, strict_decoding, and the alpha composition mode of
// heif_color_conversion_options_ext: none / solid colour / checkerboard) so
// they are fuzzed too; the rest is the file.

#include <libheif/heif.h>

#include <cstddef>
#include <cstdint>

struct Target {
  heif_colorspace cs;
  heif_chroma chroma;
};

static const Target kTargets[] = {
    {heif_colorspace_undefined, heif_chroma_undefined},
    {heif_colorspace_RGB, heif_chroma_interleaved_RGB},
    {heif_colorspace_RGB, heif_chroma_interleaved_RGBA},
    {heif_colorspace_RGB, heif_chroma_interleaved_RRGGBB_BE},
    {heif_colorspace_RGB, heif_chroma_interleaved_RRGGBBAA_BE},
    {heif_colorspace_RGB, heif_chroma_interleaved_RRGGBB_LE},
    {heif_colorspace_RGB, heif_chroma_interleaved_RRGGBBAA_LE},
    {heif_colorspace_RGB, heif_chroma_444},
    {heif_colorspace_YCbCr, heif_chroma_420},
    {heif_colorspace_YCbCr, heif_chroma_422},
    {heif_colorspace_YCbCr, heif_chroma_444},
    {heif_colorspace_monochrome, heif_chroma_monochrome},
};

static void touch_planes(const heif_image* img)
{
  // Read every byte of every plane the image claims to have, using the
  // geometry the API reports, as an application would.
  const heif_channel channels[] = {heif_channel_Y, heif_channel_Cb, heif_channel_Cr,
                                   heif_channel_R, heif_channel_G, heif_channel_B,
                                   heif_channel_Alpha, heif_channel_interleaved};
  volatile uint8_t sink = 0;
  for (heif_channel c : channels) {
    if (!heif_image_has_channel(img, c)) continue;
    size_t stride = 0;
    const uint8_t* p = heif_image_get_plane_readonly2(img, c, &stride);
    if (!p) continue;
    int w = heif_image_get_width(img, c);
    int h = heif_image_get_height(img, c);
    int bpp = heif_image_get_bits_per_pixel(img, c);  // storage bits per pixel
    if (w <= 0 || h <= 0 || bpp <= 0) continue;
    size_t row_bytes = (size_t(w) * size_t(bpp) + 7) / 8;
    for (int y = 0; y < h; y++) {
      sink ^= p[size_t(y) * stride];
      sink ^= p[size_t(y) * stride + row_bytes - 1];
    }
  }
  (void) sink;
}

static void decode_all(heif_image_handle* handle, heif_decoding_options* opts)
{
  for (const Target& t : kTargets) {
    heif_image* img = nullptr;
    heif_error err = heif_decode_image(handle, &img, t.cs, t.chroma, opts);
    if (err.code == heif_error_Ok && img) {
      touch_planes(img);
      heif_image_release(img);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 2) return 0;
  uint8_t sel = data[0];
  data++;
  size--;

  heif_context* ctx = heif_context_alloc();
  if (!ctx) return 0;
  heif_security_limits* limits = heif_context_get_security_limits(ctx);
  limits->max_image_size_pixels = 4096 * 4096;
  limits->max_memory_block_size = 256 * 1024 * 1024;

  heif_error err = heif_context_read_from_memory_without_copy(ctx, data, size, nullptr);
  if (err.code != heif_error_Ok) {
    heif_context_free(ctx);
    return 0;
  }

  heif_decoding_options* opts = heif_decoding_options_alloc();
  opts->ignore_transformations = (sel & 1);
  opts->convert_hdr_to_8bit = (sel & 2) ? 1 : 0;
  opts->strict_decoding = (sel & 4) ? 1 : 0;
  heif_color_conversion_options_ext* ext = heif_color_conversion_options_ext_alloc();
  ext->alpha_composition_mode = static_cast<heif_alpha_composition_mode>((sel >> 3) % 3);
  opts->color_conversion_options_ext = ext;

  int n = heif_context_get_number_of_top_level_images(ctx);
  if (n > 8) n = 8;
  heif_item_id ids[8];
  n = heif_context_get_list_of_top_level_image_IDs(ctx, ids, n);
  for (int i = 0; i < n; i++) {
    heif_image_handle* h = nullptr;
    if (heif_context_get_image_handle(ctx, ids[i], &h).code == heif_error_Ok) {
      decode_all(h, opts);
      heif_image_handle_release(h);
    }
  }

  opts->color_conversion_options_ext = nullptr;
  heif_color_conversion_options_ext_free(ext);
  heif_decoding_options_free(opts);
  heif_context_free(ctx);
  return 0;
}
