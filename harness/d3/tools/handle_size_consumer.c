/* A typical libheif consumer: size the output from the image handle, decode,
 * copy the rows. This is the pattern GHSA-vv35-6hxg-95x8 describes for bit
 * depth (an application that trusts the handle reads out of bounds when the
 * decoded image contradicts it); here it is applied to width and height.
 *
 *   handle_size_consumer file.heif
 * Exit 0 and "consistent" if the decoded image matches the handle; with a
 * 'clap' that extends past the image, ASan reports the over-read below.
 */
#include <libheif/heif.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv)
{
  struct heif_context* ctx = heif_context_alloc();
  if (heif_context_read_from_file(ctx, argv[1], NULL).code) return 2;
  struct heif_image_handle* h = NULL;
  if (heif_context_get_primary_image_handle(ctx, &h).code) return 2;

  int w = heif_image_handle_get_width(h);    /* what the file declares */
  int hh = heif_image_handle_get_height(h);
  unsigned char* out = malloc((size_t) w * hh);

  struct heif_image* img = NULL;
  if (heif_decode_image(h, &img, heif_colorspace_monochrome, heif_chroma_monochrome, NULL).code) return 2;
  size_t stride = 0;
  const unsigned char* p = heif_image_get_plane_readonly2(img, heif_channel_Y, &stride);
  printf("handle %dx%d, decoded %dx%d\n", w, hh,
         heif_image_get_width(img, heif_channel_Y), heif_image_get_height(img, heif_channel_Y));
  for (int y = 0; y < hh; y++)               /* rows/columns from the handle */
    memcpy(out + (size_t) y * w, p + (size_t) y * stride, (size_t) w);
  unsigned sum = 0;                          /* use the copy, so it is not optimised away */
  for (size_t i = 0; i < (size_t) w * hh; i++) sum += out[i];
  printf("consistent (checksum %u)\n", sum);
  free(out);
  heif_image_release(img);
  heif_image_handle_release(h);
  heif_context_free(ctx);
  return 0;
}
