# garak-derived axis — 2026-10-25

111 cases extracted from garak 0.17.1 probe structure.
Same signals as the encoding matrix; benign pages included as controls.

| Signal | Result |
|---|---|
| Any finding | 75.7% |
| Medium+ | 57.7% |
| Verdict suspicious+ | 57.7% |
| **Instruction recovered** | **73.9%** |

| Family | n | medium+ | recovered | verdict |
|---|---|---|---|---|
| encoding | 60 | 100% | 100% | 100% |
| smuggling | 6 | 66.7% | 66.7% | 66.7% |
| suffix | 13 | 0% | 100% | 0% |
| sysprompt_extraction | 28 | 0% | 17.9% | 0% |
| web_injection | 4 | 0% | 0% | 0% |

| Split | n | recovered |
|---|---|---|
| dev | 56 | 73.2% |
| holdout | 55 | 74.5% |

Benign controls: 26 pages, any 3.8%, medium+ 0%, verdict 0%

> Extracted offline from garak probe definitions; no garak or model at runtime.
