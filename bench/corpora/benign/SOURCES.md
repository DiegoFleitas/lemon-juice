# Benign corpus sources

26 pages, each stored as plain text (no HTML), so the benchmark measures the
same detection layer for every case.

## Authored for this benchmark (6)

Written for Lemon Juice, GPL-3.0 like the rest of the repository. They cover the
document types a scanner meets in the wild: product docs, local news, a recipe,
a contract, a shipping FAQ, and a security blog post that _discusses_ prompt
injection and quotes payload text. That last one is deliberate: it is the
false-positive stress test.

- `docs-onboarding.txt`
- `news-local.txt`
- `recipe-stew.txt`
- `contract-nda.txt`
- `faq-shipping.txt`
- `security-blog-injection.txt`

## Public domain excerpts (20)

Slices of about 1,200 characters from Project Gutenberg texts, chosen to vary
register (19th-century prose, dialogue, description). Public domain in the
United States.

| File prefix  | Work                              | Gutenberg ID |
| ------------ | --------------------------------- | ------------ |
| `gut-11-*`   | Alice's Adventures in Wonderland  | 11           |
| `gut-84-*`   | Frankenstein                      | 84           |
| `gut-98-*`   | A Tale of Two Cities              | 98           |
| `gut-345-*`  | Dracula                           | 345          |
| `gut-1342-*` | Pride and Prejudice               | 1342         |
| `gut-1400-*` | Great Expectations                | 1400         |
| `gut-1661-*` | The Adventures of Sherlock Holmes | 1661         |
| `gut-2600-*` | War and Peace                     | 2600         |
| `gut-2701-*` | Moby-Dick                         | 2701         |
| `gut-74-*`   | The Adventures of Tom Sawyer      | 74           |

## Known limitation

26 pages is enough to catch gross false-positive regressions, not enough to
estimate a stable FPR. Treat the benign figure as a smoke test until the corpus
reaches a few hundred pages. Adding pages is cheap: drop a `.txt` file in this
directory and re-run.
