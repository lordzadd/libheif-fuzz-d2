// handle_contract_fuzzer: check that a decoded image matches what its image
// handle declared, for every top-level image, its alpha and depth auxiliary
// images and its thumbnails.
//
// Why: an application sizes its reads from the handle (width, height, luma and
// chroma bit depth, alpha). If the decoded image disagrees, a conforming
// application reads out of bounds. Upstream treated this as a vulnerability
// (GHSA-vv35-6hxg-95x8) and, after the pinned commit, closed three ways to
// cause it: the codec configuration box, grid tiles and overlays. This target
// looks for any remaining way. On a mismatch it prints
//   CONTRACT-VIOLATION <what> handle=<a> image=<b> item=<id> ...
// and aborts, so sweep_run.py records a distinct signature per property.
//
// The library is unchanged; decoding uses only public API calls with the
// image's native colorspace (heif_colorspace_undefined), so no colour
// conversion is involved. The first input byte selects ignore_transformations.

#include <libheif/heif.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>

static const char* g_what = "";

[[noreturn]] static void violation(const char* what, long a, long b, heif_item_id id)
{
  fprintf(stderr, "CONTRACT-VIOLATION %s handle=%ld image=%ld item=%u (%s)\n", what, a, b, id, g_what);
  abort();
}

static heif_channel luma_channel(const heif_image* img)
{
  if (heif_image_has_channel(img, heif_channel_Y)) return heif_channel_Y;
  if (heif_image_has_channel(img, heif_channel_interleaved)) return heif_channel_interleaved;
  if (heif_image_has_channel(img, heif_channel_R)) return heif_channel_R;
  return heif_channel_Y;
}

static void check(heif_image_handle* h, bool ignore_transformations, const char* what)
{
  g_what = what;
  heif_decoding_options* opts = heif_decoding_options_alloc();
  opts->ignore_transformations = ignore_transformations;
  heif_image* img = nullptr;
  heif_error err = heif_decode_image(h, &img, heif_colorspace_undefined, heif_chroma_undefined, opts);
  heif_decoding_options_free(opts);
  if (err.code != heif_error_Ok || !img) return;

  heif_item_id id = heif_image_handle_get_item_id(h);

  // size: handle width/height are after transformations, ispe before them
  long hw = ignore_transformations ? heif_image_handle_get_ispe_width(h) : heif_image_handle_get_width(h);
  long hh = ignore_transformations ? heif_image_handle_get_ispe_height(h) : heif_image_handle_get_height(h);
  long iw = heif_image_get_primary_width(img);
  long ih = heif_image_get_primary_height(img);
  if (hw > 0 && hh > 0) {
    if (iw < hw) violation("width", hw, iw, id);
    if (ih < hh) violation("height", hh, ih, id);
  }

  // luma bit depth: only for formats where the handle's value is defined per sample
  heif_colorspace cs = heif_image_get_colorspace(img);
  heif_chroma chroma = heif_image_get_chroma_format(img);
  int hl = heif_image_handle_get_luma_bits_per_pixel(h);
  if (hl > 0 && (cs == heif_colorspace_YCbCr || cs == heif_colorspace_monochrome ||
                 (cs == heif_colorspace_RGB && chroma == heif_chroma_444))) {
    int il = heif_image_get_bits_per_pixel_range(img, luma_channel(img));
    // reading with the handle's depth over-reads when the handle claims more
    // storage bytes per sample than the image has
    if ((hl > 8) != (il > 8)) violation("luma_bits", hl, il, id);
  }
  int hc = heif_image_handle_get_chroma_bits_per_pixel(h);
  if (hc > 0 && cs == heif_colorspace_YCbCr && heif_image_has_channel(img, heif_channel_Cb)) {
    int ic = heif_image_get_bits_per_pixel_range(img, heif_channel_Cb);
    if ((hc > 8) != (ic > 8)) violation("chroma_bits", hc, ic, id);
  }

  // alpha: an application that sees has_alpha_channel() reads the alpha plane
  if (heif_image_handle_has_alpha_channel(h) && !ignore_transformations &&
      !heif_image_has_channel(img, heif_channel_Alpha) &&
      !(cs == heif_colorspace_RGB && (chroma == heif_chroma_interleaved_RGBA ||
                                      chroma == heif_chroma_interleaved_RRGGBBAA_BE ||
                                      chroma == heif_chroma_interleaved_RRGGBBAA_LE)))
    violation("alpha_missing", 1, 0, id);

  heif_image_release(img);
}

static void check_tree(heif_image_handle* h, bool ign)
{
  check(h, ign, "image");

  heif_image_handle* a = nullptr;
  int naux = heif_image_handle_get_number_of_auxiliary_images(h, 0);
  if (naux > 0 && naux < 16) {
    heif_item_id ids[16];
    naux = heif_image_handle_get_list_of_auxiliary_image_IDs(h, 0, ids, naux);
    for (int i = 0; i < naux; i++)
      if (heif_image_handle_get_auxiliary_image_handle(h, ids[i], &a).code == heif_error_Ok) {
        check(a, ign, "auxiliary");
        heif_image_handle_release(a);
      }
  }
  if (heif_image_handle_has_depth_image(h)) {
    heif_item_id did;
    if (heif_image_handle_get_list_of_depth_image_IDs(h, &did, 1) == 1 &&
        heif_image_handle_get_depth_image_handle(h, did, &a).code == heif_error_Ok) {
      check(a, ign, "depth");
      heif_image_handle_release(a);
    }
  }
  int nt = heif_image_handle_get_number_of_thumbnails(h);
  if (nt > 0 && nt < 16) {
    heif_item_id ids[16];
    nt = heif_image_handle_get_list_of_thumbnail_IDs(h, ids, nt);
    for (int i = 0; i < nt; i++)
      if (heif_image_handle_get_thumbnail(h, ids[i], &a).code == heif_error_Ok) {
        check(a, ign, "thumbnail");
        heif_image_handle_release(a);
      }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 2) return 0;
  bool ign = data[0] & 1;
  data++;
  size--;
  heif_context* ctx = heif_context_alloc();
  heif_security_limits* limits = heif_context_get_security_limits(ctx);
  limits->max_image_size_pixels = 4096 * 4096;
  if (heif_context_read_from_memory_without_copy(ctx, data, size, nullptr).code == heif_error_Ok) {
    heif_item_id ids[8];
    int n = heif_context_get_list_of_top_level_image_IDs(ctx, ids, 8);
    for (int i = 0; i < n; i++) {
      heif_image_handle* h = nullptr;
      if (heif_context_get_image_handle(ctx, ids[i], &h).code == heif_error_Ok) {
        check_tree(h, ign);
        heif_image_handle_release(h);
      }
    }
  }
  heif_context_free(ctx);
  return 0;
}
