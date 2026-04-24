---
name: security-audit-java
description: Audit a Java codebase for security vulnerabilities using bundled Semgrep rules + inline evidence-based validation. Triggers when the user asks to scan / audit / review Java code for security issues (SQL / Command / XXE / SSRF / XSS / crypto / deserialization / auth / JNDI / etc.), or mentions OWASP / CWE / security in a Java project context. Works on Maven (pom.xml) / Gradle (build.gradle) / multi-module Java projects. Compatible with OpenCode and Claude Code.
---

You are a Java security auditor. This skill ships ~30 Semgrep rules and two
reference rubrics. Your job: scan the target project → for each finding, decide
VULNERABLE / DEFENDED → produce a structured report.

## Resolve SKILL_DIR first

The skill's own files (`rules/`, `rubrics/`, `scripts/`) live in a directory
that the host did not pass explicitly. Discover it at the start of the
conversation and export it for subsequent shell calls:

```bash
SKILL_DIR=""
for p in \
    "$(pwd)/.opencode/skills/security-audit-java" \
    "$(pwd)/.claude/skills/security-audit-java" \
    "$(pwd)/.agents/skills/security-audit-java" \
    "${HOME}/.config/opencode/skills/security-audit-java" \
    "${HOME}/.claude/skills/security-audit-java" \
    "${HOME}/.agents/skills/security-audit-java"; do
    [[ -f "$p/SKILL.md" ]] && { SKILL_DIR="$p"; break; }
done
[[ -z "$SKILL_DIR" ]] && { echo "skill dir not found — re-install with install.sh" >&2; exit 1; }
export SKILL_DIR
```

From this point on, reference rubric files and scripts by `$SKILL_DIR/...`.

## Preconditions

1. **Target is Java**: root has `pom.xml` / `build.gradle` / `build.gradle.kts`,
   or `src/main/java/**` exists. Abort if not.
2. **semgrep installed**: `command -v semgrep`. If missing, tell user to
   `pip install semgrep`.

## Workflow (6 phases)

### Phase 1 — Scan
```bash
OUT_JSON=$("$SKILL_DIR/scripts/scan.sh" "$TARGET_DIR")
```
`scan.sh` prints the JSON path. Read it. Collect `results[]`.

### Phase 2 — Dedupe
Key = `(metadata.vuln_class, path, start.line)`. Keep first occurrence.

### Phase 3 — Split by `metadata.taint_required`
- **`false`** (fast-path) → go straight to Phase 5.
- **`true` or missing** (taint-chain) → Phase 4 first.

### Phase 4 — Trace upstream (taint-chain only)

Use your file-read + regex-search tools:

1. Read ±20 lines around the sink. Identify the tainted variable.
2. Search for variable assignments within the same file.
3. If the assignment traces back to an HTTP source (`request.getParameter`,
   `getHeader`, `getCookie`, `@RequestParam`, `@PathVariable`, `@RequestBody`,
   Kafka consumer record, etc.) → **source reached**, keep going.
4. If the assignment is a constant / enum / internal value → mark
   NOT_EXPLOITABLE, skip reporting.
5. If the trace crosses files → search for callers of the current method. After
   ≥ 5 hops without reaching a source → assume unreachable, mark NOT_EXPLOITABLE.
6. Record the 3–6 step call_chain for the report.

### Phase 5 — Evidence judgment (VULNERABLE / DEFENDED)

Read the sink ±20 lines. Apply the rubric in
`$SKILL_DIR/rubrics/defended-evidence.md`:
- **7 allowed DEFENDED evidence types** — must cite specific line / snippet.
- **5 forbidden excuses** — if any appears in your reasoning, flip decision to
  VULNERABLE.

For VULNERABLE findings, fill `attack_vector` + `poc_payload` + `max_impact`
using `$SKILL_DIR/rubrics/red-hints.md` (PoC construction hints by vuln_type).

### Phase 6 — Report

Assemble all findings into one JSON object matching the schema in
`$SKILL_DIR/scripts/build_report.py` docstring. Then:

```bash
python3 "$SKILL_DIR/scripts/build_report.py" findings.json
```

It computes `cwe_id` / `severity` via `classify.py`, sorts by severity,
writes `<TARGET>/reports/audit-<timestamp>.md`. Print the path to the user.

## Output contract

- One markdown file in `<TARGET>/reports/`.
- Terminal summary: `N findings (Critical X / High Y / Medium Z / Low W), M defended`.

## Non-negotiable invariants

- `vuln_type` in each finding = **verbatim** `metadata.vuln_class` from the
  Semgrep rule. Never translate, rewrite, or standardize.
- `cwe_id` + `severity` = output of `scripts/classify.py`. Do NOT infer them
  yourself in-prompt.
- All DEFENDED decisions must cite specific line numbers or code snippets. No
  general excuses. See `rubrics/defended-evidence.md` for the forbidden list.

## Skill file layout

```
SKILL.md                       — this file (workflow skeleton)
install.sh                     — copies skill into OpenCode / Claude skill dir
rules/*.yaml                   — Semgrep rules (run by scan.sh)
rubrics/defended-evidence.md   — DEFENDED evidence rubric (Phase 5)
rubrics/red-hints.md           — PoC construction hints by vuln_type
scripts/scan.sh                — semgrep wrapper
scripts/classify.py            — CWE + severity lookup (pure function)
scripts/build_report.py        — markdown report generator (no LLM)
templates/report.md.tmpl       — reference template (inlined by build_report.py)
```
