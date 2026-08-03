# Security review notes

Lemon Juice is a prompt-injection **detector**. Its source therefore carries a
corpus of attack-payload strings (`eval(`, `os.system(`, `bash -i >& /dev/tcp/`,
LLM control tokens) as inert regex pattern data. Static scanners that grep
source without parsing it will match those strings and report the extension as
if it _performed_ the behavior it _detects_.

This file pre-resolves that class of finding, with citations you can check
yourself. It is for AMO reviewers, enterprise allowlist processes, downstream
packagers, and whoever receives the next automated scanner report.

## Finding: "Dynamic code execution via `eval()`"

> The extension calls `eval()`, which executes an arbitrary string as code at
> runtime. This is a primary mechanism for loading obfuscated or remotely-fetched
> payloads.

**False positive. The extension does not call `eval()`.**

The only occurrence of `eval` in any shipped file is a regex literal in the
`CODE_EXECUTION_PATTERNS` array (`detectors.js`, `CODE_EXECUTION_PATTERNS`,
~line 888):

```js
/\beval\s*\(/i,
```

That array has exactly one consumer, `scanCodeExecution()` (`detectors.js`,
~line 902), which does:

```js
const m = re.exec(text);
```

`RegExp.prototype.exec` is a string match. The matched substring is stored on a
plain finding object (`{ type, severity, index, match, pattern }`) and rendered
as text in the popup. It is never passed to an execution sink. The extension's
purpose is to tell you when a _web page_ contains such a payload.

The second `eval` hit in `detectors.js` (~line 910) is a code comment explaining
why bare `eval(`/`exec(` matches are rated LOW rather than HIGH.

Supporting facts:

- `manifest.json` ships
  `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'self'" }`.
  Manifest V3 forbids `eval` in extension pages regardless of source.
- No `new Function`, string-form `setTimeout`/`setInterval`, `innerHTML`,
  `outerHTML`, `insertAdjacentHTML`, `document.write`, or dynamic `import()`
  appears in any shipped file.
- `browser.scripting.executeScript` (`popup.js`, three call sites) is always
  invoked with `files:` (a static array of local filenames) or `func:` (a static
  function reference). It never receives a string to execute, and every argument
  is a literal in the source rather than fetched content.
- The `page.evaluate(...)` calls are Playwright test harness code under
  `__tests__/e2e/`. They are not shipped. See "What actually ships" below.
- The extension makes **zero network calls**. There is no remote payload to load.

## Other RCE- and exfil-shaped strings in this repo

Same explanation, different strings. All of these are `RegExp` operands:

| Strings present in source                                                                                                                     | Where                                                       | What they are                              |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------ |
| `eval(`, `exec(`, `compile(`, `os.system(`, `os.popen(`, `subprocess.run(`, `__import__(`, `pickle.loads(`, `pty.spawn(`, `__class__.__mro__` | `CODE_EXECUTION_PATTERNS` in `detectors.js`                 | Regex literals matched against page text   |
| `bash -i >& /dev/tcp/`, `nc -e /bin/sh`, `ncat --exec`, `python -c 'import os'`                                                               | `REVERSE_SHELL_PATTERNS` in `detectors.js`                  | Regex literals matched against page text   |
| `<\|im_start\|>`, `[INST]`, `</system>`                                                                                                       | `CONTROL_TOKENS` in `detectors.js`                          | Regex literals matched against page text   |
| Full attack payloads, verbatim                                                                                                                | `__tests__/detectors.test.js`, `docs/plans/`, HTML fixtures | Test fixtures and design docs; not shipped |

**The invariant:** every one of these strings reaches exactly one sink, the
`re.exec(text)` call inside a `scanX` function in `detectors.js`, and the result
is a plain object that gets rendered as text. The strings are only ever matched
against page content. Nothing executes them, passes them to a shell, or sends
them over the network.

`detectors.js` is also deliberately DOM-free: it takes a string and returns
findings, with no `document`/`window` access. All DOM work lives in
`scan-helpers.js` and `scan.js`.

## Permissions and network posture

- **Permissions:** `activeTab` and `scripting` only. No host permissions.
- **Scope of access:** scanning happens only on the tab that is active when you
  click the toolbar icon, and only for that interaction.
- **Network:** no network calls, no telemetry, no analytics. All decoding and
  scanning is local to the content-script sandbox. `manifest.json` declares
  `data_collection_permissions: { required: ["none"] }`.
- **`web_accessible_resources`:** lists `detectors.js`, `scan-helpers.js`, and
  `scan.js` so those three files can be injected into the active tab as content
  scripts. They contain detection logic only.
- Cross-origin iframes are deliberately **not** reached. Iframe traversal stops
  at same-origin `contentDocument` access rather than using
  `executeScript({ allFrames: true })`, which would require broader access.

## What actually ships

`pnpm run package` zips exactly six source files plus icons:

```
manifest.json  popup.html  detectors.js  scan-helpers.js  scan.js  popup.js  icons/
```

Tests (`__tests__/`), design docs (`docs/`), and tooling (`scripts/`) are not in
the artifact.

## Verify it yourself

Run these from a repo checkout.

```sh
# 1. Every `eval` occurrence in shipped files, with context.
grep -n "eval" manifest.json popup.html detectors.js scan-helpers.js scan.js popup.js
# Expect exactly two hits, both in detectors.js: one regex literal, one comment.

# 2. No dynamic-execution sinks anywhere in shipped files.
grep -nE "new Function|document\.write|innerHTML|insertAdjacentHTML|import\(" \
  manifest.json popup.html detectors.js scan-helpers.js scan.js popup.js
# Expect no output.

# 3. Confirm what the build actually contains.
pnpm run package && unzip -l dist/lemon-juice.zip
# Expect 9 entries: the 6 source files, icons/, and 2 PNGs. No tests, no docs.
```

To confirm the detector _behavior_ rather than its absence of side effects, run
`pnpm test`. `__tests__/detectors.test.js` asserts that `scanCodeExecution`
returns findings for payload strings and rates bare `eval(`/`exec(` as LOW,
precisely because they appear so often in legitimate code documentation.
