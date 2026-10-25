# garak-derived axis — 2026-10-25

73 cases extracted from garak 0.17.1 probe structure.
Same signals as the encoding matrix; benign pages included as controls.

| Signal | Result |
|---|---|
| Any finding | 31.5% |
| Medium+ | 13.7% |
| Verdict suspicious+ | 13.7% |
| **Instruction recovered** | **31.5%** |

| Family | n | medium+ | recovered | verdict |
|---|---|---|---|---|
| encoding | 60 | 16.7% | 16.7% | 16.7% |
| suffix | 13 | 0% | 100% | 0% |

| Split | n | recovered |
|---|---|---|
| dev | 37 | 32.4% |
| holdout | 36 | 30.6% |

Benign controls: 26 pages, any 3.8%, medium+ 0%, verdict 0%

> Extracted offline from garak probe definitions; no garak or model at runtime.
