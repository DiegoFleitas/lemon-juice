# garak-derived axis — 2026-10-25

73 cases extracted from garak 0.17.1 probe structure.
Same signals as the encoding matrix; benign pages included as controls.

| Signal | Result |
|---|---|
| Any finding | 100% |
| Medium+ | 82.2% |
| Verdict suspicious+ | 82.2% |
| **Instruction recovered** | **100%** |

| Family | n | medium+ | recovered | verdict |
|---|---|---|---|---|
| encoding | 60 | 100% | 100% | 100% |
| suffix | 13 | 0% | 100% | 0% |

| Split | n | recovered |
|---|---|---|
| dev | 37 | 100% |
| holdout | 36 | 100% |

Benign controls: 26 pages, any 3.8%, medium+ 0%, verdict 0%

> Extracted offline from garak probe definitions; no garak or model at runtime.
