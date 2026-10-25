# garak-derived axis — 2026-10-25

111 cases extracted from garak 0.17.1 probe structure.
Same signals as the encoding matrix; benign pages included as controls.

| Signal | Result |
|---|---|
| Any finding | 100% |
| Medium+ | 60.4% |
| Verdict suspicious+ | 60.4% |
| **Instruction recovered** | **100%** |

| Family | n | medium+ | recovered | verdict |
|---|---|---|---|---|
| encoding | 60 | 100% | 100% | 100% |
| smuggling | 6 | 100% | 100% | 100% |
| suffix | 13 | 0% | 100% | 0% |
| sysprompt_extraction | 28 | 3.6% | 100% | 3.6% |
| web_injection | 4 | 0% | 100% | 0% |

| Split | n | recovered |
|---|---|---|
| dev | 56 | 100% |
| holdout | 55 | 100% |

Benign controls: 26 pages, any 3.8%, medium+ 0%, verdict 0%

> Extracted offline from garak probe definitions; no garak or model at runtime.
