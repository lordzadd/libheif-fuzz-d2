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

## Campaign C (phased cloud campaign, long2*)

Campaign C: 3 phases, 13.841 CPU-hours, 115665718 executions, 0 artifacts. Campaign B + C: 25.137 CPU-hours.

| phase | workers | wall s | CPU-hours | executions | artifacts | interrupted |
|---|---|---|---|---|---|---|
| long2a | file=1, api=1, tile=1 | 5407.9 | 4.635 | 46125834 | 0 | no |
| long2b | file=1, api=1, sequence=1 | 5407.5 | 4.51 | 46679677 | 0 | no |
| long2c | tile=1, file=1, box=1 | 5407.4 | 4.696 | 22860207 | 0 | no |
| total |  | 16222.8 | 13.841 | 115665718 | 0 |  |

## Campaign C union edge coverage, first and last checkpoint per phase

| phase | target | first t (s) | first cov | last t (s) | last cov | last ft | corpus units |
|---|---|---|---|---|---|---|---|
| long2a | api_fuzzer | 43.62 | 10988 | 5149.84 | 11931 | 41683 | 21009 |
| long2a | file_fuzzer | 40.69 | 10304 | 5139.67 | 10771 | 33725 | 13419 |
| long2a | tile_fuzzer | 49.96 | 10449 | 5185.08 | 11256 | 44349 | 19878 |
| long2b | api_fuzzer | 312.97 | 12267 | 4664.37 | 12561 | 45077 | 28083 |
| long2b | file_fuzzer | 291.24 | 11124 | 4650.18 | 11387 | 36659 | 18960 |
| long2b | sequence_fuzzer | 319.18 | 7779 | 4685.83 | 8322 | 21326 | 14803 |
| long2c | box_fuzzer | 316.99 | 6168 | 4927.93 | 6390 | 20088 | 16527 |
| long2c | file_fuzzer | 311.04 | 11491 | 4903.88 | 11570 | 37975 | 22914 |
| long2c | tile_fuzzer | 45.84 | 11572 | 4714.69 | 11794 | 48203 | 26085 |

## Coverage added by the generated seeds (seed_gain.py)

| seed set of | target | B inputs | B cov | gen inputs | gen cov | B+gen cov | gain over B |
|---|---|---|---|---|---|---|---|
| long2a | api_fuzzer | 46143 | 9972 | 400 | 6098 | 10894 | +922 (+9.2%) |
| long2a | file_fuzzer | 22174 | 9157 | 400 | 6098 | 10307 | +1150 (+12.6%) |
| long2a | tile_fuzzer | 19662 | 9185 | 400 | 5937 | 10336 | +1151 (+12.5%) |
| long2b | api_fuzzer | 46143 | 9972 | 700 | 6709 | 11312 | +1340 (+13.4%) |
| long2b | file_fuzzer | 22174 | 9157 | 700 | 6684 | 10727 | +1570 (+17.1%) |
| long2b | tile_fuzzer | 19662 | 9185 | 700 | 6492 | 10633 | +1448 (+15.8%) |

## Independent verification of campaign A findings

| build | cases | non-zero exits |
|---|---|---|
| baseline (4cb65ae) | 22 | 22 |
| fixed (660f468) | 22 | 0 |

## Replay (before/after)

| label | replay rows | non-zero exits |
|---|---|---|
| baseline | 13 | 2 |
| long2-baseline | 5 | 0 |
| long2-genseeds-baseline | 3 | 0 |
| long2-patched | 5 | 0 |
| patched | 13 | 0 |
| seedcorpus | 6 | 0 |

