# Campaign analysis: baseline

Wall clock: 7366.1 s (2.05 h). Workers: 12. CPU time: 40664.2 s = 11.30 CPU-hours.

| fuzzer | workers | execs | max worker edges | final corpus units | final corpus bytes | crashes |
|---|---|---|---|---|---|---|
| api_fuzzer | 3 | 11270649 | 9969 | 46143 | 69499150 | 0 |
| box_fuzzer | 2 | 13999177 | 6091 | 39205 | 4847967 | 6 |
| color_conversion_fuzzer | 1 | 47154395 | 1625 | 2146 | 2805533 | 0 |
| file_fuzzer | 3 | 1898301 | 9156 | 22174 | 44895868 | 6 |
| sequence_fuzzer | 2 | 11025842 | 7745 | 35577 | 39355915 | 2 |
| tile_fuzzer | 1 | 2824963 | 9184 | 19662 | 29659811 | 0 |

Total executions: 88173327.

