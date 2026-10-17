# redact-engine

**Project a local activity stream into something a model may read — with the
privacy boundary in the code path, not in the instructions.**

Built for one specific situation: you have a machine that recorded what you were
doing (app focus, accessibility text, window titles, chat rows), and you want an
LLM to answer questions over it. Handing it the raw stream means handing it every
address, phone number, verification code and half-typed message in the file.

## Observed on a real machine

`examples/events.jsonl` through `--verify` (output is verbatim, not illustrative):

```
$ redact-engine project --key alias.key --source examples/events.jsonl --out out --verify
{"events": 3, "aliasing": "stable", "redactions": {"credential": 1, "email": 1, "number_long": 1, "otp": 1, "phone_cn": 1}}

out/safe/events.jsonl   (dir 0700, file 0600)
{"timestamp": "2026-10-17T09:00:00", "app": "com.example.mail", "text": "reply to [email-3c97d63a591c] about the invoice for order [number_long-3e0f158ffb15]"}
{"timestamp": "2026-10-17T09:05:00", "app": "com.example.chat", "text": "您的验证码是 [otp-3dd9eb3270c0], call [phone_cn-ee6a5086aab7]"}
{"timestamp": "2026-10-17T09:10:00", "app": "com.example.ide", "text": "refactored src/parser.py, nothing personal; token [credential-42e9b4a3940b]"}
```

Note what did *not* survive: nothing. Note what did: the shape of each secret,
via its kind label. That is the trade this engine makes deliberately -- a reader
must be able to tell "there was a verification code here" from "there was nothing
here", or the projection stops being evidence about your own history.

## Why not an existing PII library

Presidio, `pii-redact`, OpenAI Privacy Filter and friends are text-level PII
removers, and they are good at that. Three things this does differently:

**1. Aliases are stable, by design.**
The replacement is `[kind-<hmac12>]`, and the HMAC key is *persistent*, so the
same person keeps the same alias across exports. A general-purpose redactor often
does the opposite on purpose (per-message keys, to block re-identification across
requests — that is a defensible design for a *cloud* pipeline). For an activity
history the requirement is inverted: without continuity you cannot answer "which
tool did I live in all week", and with a per-run random token every subject
becomes noise. This engine offers **both**, as a flag:

```bash
redact-engine project … --unstable    # fresh aliases per run: uncorrelatable exports
redact-engine project …               # stable: the same subject stays itself
```

**2. The boundary is structural, so `--verify` can actually prove it.**
`project()` reads a fixed whitelist of field names and routes every string it
does read through redaction. An unexpected key — `raw_chat_history`, an `ax_tree`
blob, a URL hidden in `title` — is not filtered out, it is **never looked at**.
That is what makes the verification meaningful rather than decorative:

```bash
redact-engine project --key alias.key --source events.jsonl --out out/ --verify
# exit 5 = a pre-redaction value survived into the output
```

A `README` that says "never print raw text" is a wish. A function that has no
code path for printing anything but whitelisted, redacted fields is a guarantee,
and `assert_no_leaks()` is the check that the guarantee held.

**3. Sources are pluggable; the core is shape-agnostic.**
Field mapping is data, so one engine reads a JSONL recorder, an accessibility
dump (`payload.lines[]`), or a browser export without the redaction rules knowing
which:

```json
{"timestamp": "ts", "app": "app.bundleIdentifier", "text": "payload.lines"}
```

## Install

```bash
pipx install redact-engine       # or: pip install redact-engine

# Not on PyPI yet (name verified free as of 2026-10-17). Until the first release:
git clone https://github.com/Test2049micro/redact-engine && cd redact-engine && pipx install .
```

Python 3.9+, no runtime dependencies, no network calls, nothing leaves the machine.

## Usage

```bash
redact-engine init-key --key ~/.local/share/redact/alias.key     # 32B, created 0600
redact-engine project --key ~/.local/share/redact/alias.key \
    --root ~/recordings --pattern '**/events.jsonl' \
    --out ./projection --verify
redact-engine redact-text --key … < note.txt > note.safe.txt
```

Output layout (modes are part of the design, not tidiness):

```
projection/safe/events.jsonl        0600, projection only, dir 0700
projection/safe/summary.json        0600, counts only -- contains no text at all
projection/consented/identity-map.json   only with --identity-map; reverses the aliases
```

```bash
$ redact-engine project --key alias.key --source examples/events.jsonl --out out --verify
{"events": 3, "aliasing": "stable", "redactions": {"credential": 1, "email": 1,
 "number_long": 1, "otp": 1, "phone_cn": 1}, "coverage_assessed": false}
```

## What it catches

Default rule kinds: `credential`, `bearer`, `secret_json`, `email`, `phone_cn`,
`id_cn`, `otp`, `url`, `path`, `guid`, `number_long`, `iban`, `ip_private`.
Restrict with `--kind email,url`; add conservative Chinese person/place cues with
`--zh-cues` (labelled as heuristics — they are not NER, and the CLI says which
extractor was in use rather than implying more than it did).

## Key handling

The alias key is the only thing that reverses the projection, so it gets the same
treatment as a secret: created `O_EXCL` mode `0600` inside a `0700` directory, and
refused if it is a symlink, not a regular file, not owned by the reader, or
group/world readable. A silently-replaced key would relabel every subject in the
corpus, so an existing key is never overwritten without a flag. The reversible
identity map additionally writes a `.gitignore` (`*`) next to itself.

## Limits, stated plainly

- **Recall is the real risk, and regex recall is bounded.** A name written without
  an honorific, a phone number spelled with spaces or full-width digits, prose
  that *is* the sensitive content — none of these are caught by shape matching.
  Run with `--verify` and treat the counts as a floor, not a certificate.
- **Whitelisting a field means trusting it to hold telemetry, not prose.** If
  `app` legitimately contains a window title with a person's name, that text is
  redacted by rule but the *sentence around it* survives. Narrow `--fields`.
- **No images, no OCR, no clipboard history.** Text in.
- **English and Chinese patterns only.** Other locales need rules, not promises.
- **`coverage_assessed: false` is always reported.** "No records found" is not
  "nothing happened": it usually means the recorder is not writing where we are
  looking, and a projection that quietly looked complete would be the worst
  failure mode of all.

## Development

```bash
python -m unittest discover -s tests -v     # 43 tests, zero dependencies
```

Coverage is weighted toward the failures that would be *lies* rather than
inconveniences: symlinked key and output refused, group/world-readable key
refused, a malformed source line skipped instead of aborting mid-file, unknown
fields never emitted, `--unstable` verified to break cross-run correlation, and
`--verify` proven to catch a forced leak (a rule set that cannot see emails is
caught by it, not praised by it).

## 中文摘要

给「本机录下了你在做什么，想让模型帮你分析」这条路径做脱敏投影，和通用 PII 库有三个
取向差别：① 别名用**持久密钥**的 HMAC，同一个人跨导出保持同一个 `[kind-hash]`——云端
管道常故意做反（每条消息独立密钥以阻止关联），但活动历史要的是连续性，这里用
`--unstable` 两个方向都给你选；② 边界是**结构性的**：投影函数只读固定白名单字段，
`raw_chat_history` 这类意外字段不是被过滤掉，而是根本不会被读——所以 `--verify` 的
「把脱敏前的值再在输出里搜一遍」是有意义的证明而不是装饰，命中即退出码 5；③ 数据源
形状用 mapping JSON 声明，核心不认识任何厂商的格式。密钥 0600/目录 0700、拒绝符号链接
与非属主、已存在密钥不静默覆盖、可逆身份映射默认写 `.gitignore`。诚实的边界：正则
召回有限，姓名不带称谓、号码被空格或全角数字打断、正文本身就是敏感内容这几类抓不住；
所以 `--verify` 只保证「规则命中的都没漏」，不保证「什么都没说出去」。空结果一律标
`coverage_assessed=false`——「没记录」不等于「没发生」。

## License

MIT
