# DEFENDED Evidence Rubric

This is the strict rubric for deciding whether a Semgrep finding is a true
vulnerability (VULNERABLE) or a safe-in-context usage (DEFENDED). Applied in
skill Phase 5.

---

## ✅ Allowed DEFENDED evidence (must cite line / snippet)

A finding may be marked **DEFENDED** only if at least one of the following
code-level facts is true AND the analysis text quotes the specific line number
or code that demonstrates it:

1. **Dead code**
   Sink's function / branch is unreachable:
   - No callers (grep across the repo returns zero hits)
   - Inside a forever-false condition (`if (false)` / `if (DEBUG && ...)`)
   - `@Deprecated` + empty body

2. **Downstream overwrite**
   Right after the sink, the dangerous value is replaced with a safe one.
   E.g., a `KeyGenerator.getInstance("DES")` whose resulting key is
   immediately reassigned with `KeyGenerator.getInstance("AES").generateKey()`
   before any encryption call.

3. **Scenario insensitive**
   `new Random()` demonstrably only used for UI animation / test data / random
   sampling of non-secure values, never feeding into a security decision.
   Must cite the consuming call and show it's non-security-relevant.

4. **SDK-internal parameter**
   The "weak" algorithm string is only a protocol-negotiation parameter passed
   to a remote peer (not used for local encrypt/decrypt/hash); the peer will
   choose the real algorithm. Example: TLS cipher suite whitelist declaration.

5. **Output already masked** (for sensitive-data-in-log / -url / stack-trace-exposure)
   Mask / redact / `substring(0,4)+"****"` / `MaskingPatternLayout` / custom
   `Converter` is applied **before** the sink. Cite the mask code location.

6. **Environment isolation**
   Sink is wrapped by `@Profile("dev"|"test")` / `@ActiveProfiles(...)` /
   `@ConditionalOnProperty` / Spring `Condition` / Maven profile. Production
   builds never reach it. The annotation / condition must be cited by name.

7. **Data is non-sensitive** (for insecure-cookie / sensitive-data-in-url)
   The cookie or URL-query only carries UI preferences / A-B test ID / language
   code / theme — never authentication, session, or PII. Evidence must be the
   variable name itself, or a comment / JavaDoc explicitly stating the intent.

---

## 🚫 Forbidden DEFENDED reasons (always VULNERABLE)

If any of these appear in your `defense_analysis`, **flip the decision to
VULNERABLE**. These are repeatedly observed LLM excuses to whitewash real bugs:

- "This is test / benchmark / demo / sample / example / lab / sonar project code."
  CWE definitions judge code **behavior**, not project kind. A real prod repo
  also contains test directories, and test code gets executed in CI.

- "Package / file / path contains `test` / `benchmark` / `demo` / `sonar` /
  `report` / `fixture`."
  Path name is not a security boundary. The real bug is that the dangerous
  shape exists in compiled bytecode somewhere.

- "Non-production credential / local-dev only / internal tool not on public net."
  CWE-798 is a per-line defect. Credentials leak through git history, backup
  copies, screen-shares. Scope irrelevance is not a defense.

- "Static scanners typically false-positive on this pattern."
  You ARE the second-pass validator. This excuse is circular — passing the
  decision back to an upstream scanner accomplishes nothing.

- "The value is hardcoded so it cannot be user-controlled."
  For fast-path sinks (CWE-327 weak crypto, CWE-798 hardcoded creds, etc.),
  user-controllability is not the issue. The dangerous shape is the issue.
