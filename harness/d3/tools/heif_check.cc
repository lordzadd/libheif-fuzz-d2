// Decode every file given on the command line and print one status line each:
//   <path>\t<ok|ERR|info>\t<message>
// Linked against the instrumented static libheif from build/, so it also shows
// whether a seed reaches pixel decode or is rejected by the parser.
#include <libheif/heif.h>
#include <libheif/heif_regions.h>
#include <cstdio>
int main(int argc, char** argv) {
  for (int i = 1; i < argc; i++) {
    heif_context* ctx = heif_context_alloc();
    heif_error e = heif_context_read_from_file(ctx, argv[i], nullptr);
    if (e.code) { printf("%s\tERR\tread: %s\n", argv[i], e.message); heif_context_free(ctx); continue; }
    heif_image_handle* h = nullptr;
    e = heif_context_get_primary_image_handle(ctx, &h);
    if (e.code) { printf("%s\tERR\tprimary: %s\n", argv[i], e.message); heif_context_free(ctx); continue; }
    int nreg = heif_image_handle_get_number_of_region_items(h);
    int nmeta = heif_image_handle_get_number_of_metadata_blocks(h, nullptr);
    printf("%s\tinfo\tregions=%d metadata=%d\n", argv[i], nreg, nmeta);
    heif_image* img = nullptr;
    e = heif_decode_image(h, &img, heif_colorspace_undefined, heif_chroma_undefined, nullptr);
    if (e.code) printf("%s\tERR\tdecode: %s\n", argv[i], e.message);
    else { printf("%s\tok\t%dx%d\n", argv[i], heif_image_get_primary_width(img), heif_image_get_primary_height(img)); heif_image_release(img); }
    heif_image_handle_release(h);
    heif_context_free(ctx);
  }
}
