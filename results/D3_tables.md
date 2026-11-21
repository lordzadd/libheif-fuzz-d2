# D3 tables (generated)

## Campaign A (team baseline)

Campaign A: 491.21 wall, 1284.98 CPU-s = 0.3569 CPU-hours, 35 rounds (5 rounds/target x 30s), 226 artifacts.

| class | description | inputs | bytes (orig -> min) | source line | ASan memory error |
|---|---|---|---|---|---|
| C1 | zero-length read into empty vector (bitstream.cc:115) | 188 | 25 -> 8 | libheif/bitstream.cc:115 | no |
| C2 | zero-length item-data copy from empty vector (heif_items.cc:170) | 31 | 813 -> 308 | libheif/api/libheif/heif_items.cc:170 | no |

## Campaign B (sustained campaign, this revision)

Campaign B: 7366 s wall, 40664.2 CPU-s = 11.296 CPU-hours, 12 workers, 14 artifacts.

| target | workers | executions | corpus units | corpus bytes | artifacts |
|---|---|---|---|---|---|
| api_fuzzer | 3 | 11270649 | 46143 | 69499150 | 0 |
| box_fuzzer | 2 | 13999177 | 39205 | 4847967 | 6 |
| color_conversion_fuzzer | 1 | 47154395 | 2146 | 2805533 | 0 |
| file_fuzzer | 3 | 1898301 | 22174 | 44895868 | 6 |
| sequence_fuzzer | 2 | 11025842 | 35577 | 39355915 | 2 |
| tile_fuzzer | 1 | 2824963 | 19662 | 29659811 | 0 |
| total |  | 88173327 | 164907 | 191064244 | 14 |

## Campaign B union edge coverage at 15-minute checkpoints

| target | 30 min | 60 min | 90 min | 120 min | maximum |
|---|---|---|---|---|---|
| api_fuzzer | 9472 | 9764 | 9886 | 9969 | 9969 |
| box_fuzzer | 5640 | 5873 | 5995 | 6091 | 6091 |
| color_conversion_fuzzer | 1625 | 1625 | 1625 | 1625 | 1625 |
| file_fuzzer | 8892 | 9062 | 9122 | 9156 | 9156 |
| sequence_fuzzer | 7422 | 7581 | 7682 | 7745 | 7745 |
| tile_fuzzer | 8691 | 8952 | 9071 | 9184 | 9184 |

## Independent verification of campaign A findings

| build | cases | non-zero exits |
|---|---|---|
| baseline (4cb65ae) | 22 | 22 |
| fixed (660f468) | 22 | 0 |

## Replay (before/after)

| label | replay rows | non-zero exits |
|---|---|---|
| baseline | 13 | 2 |
| patched | 13 | 0 |
| seedcorpus | 6 | 0 |

