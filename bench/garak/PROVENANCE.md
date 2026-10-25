# Detector corpus provenance

`bench/garak/corpus.jsonl` is generated from **garak 0.17.1** probe structure,
offline. It is committed so the detection bench needs no Python, garak, or
network at run time.

- Upstream: <https://github.com/NVIDIA/garak>, tag `v0.17.1`, Apache-2.0.
- Sources reused: `garak/probes/encoding.py` (templates and encoder names),
  `garak/data/gcg/gcg.txt` (adversarial suffix list).
- Payload text: neutral instructions authored here. Harmful base prompts from
  the suffix probe are deliberately not copied.
- Extraction: `python bench/garak/extract.py --garak-src <unpacked-wheel>
--out bench/garak/corpus.jsonl` (Python 3.12).
- Deterministic: same garak source and script produce the same 73 rows.

Garak is a model-vulnerability scanner; this corpus uses probe _shapes_ as
detector tests, not garak's probe scores.
