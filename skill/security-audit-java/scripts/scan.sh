#!/usr/bin/env bash
# Thin wrapper around semgrep for the security-audit-java skill.
# Usage: scan.sh <target_dir> [rules_dir] [output_json]

set -euo pipefail

TARGET="${1:-}"
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_DIR="${2:-${SKILL_DIR}/rules}"
OUT="${3:-/tmp/semgrep-audit-$(date +%s).json}"

if [[ -z "$TARGET" ]]; then
    echo "usage: scan.sh <target_dir> [rules_dir] [output_json]" >&2
    exit 2
fi
if ! command -v semgrep >/dev/null; then
    echo "semgrep not installed. Try: pip install semgrep" >&2
    exit 3
fi
if [[ ! -d "$RULES_DIR" ]]; then
    echo "rules directory not found: $RULES_DIR" >&2
    echo "hint: copy CodeAudit/semgrep_rules/custom/*.yaml into $RULES_DIR" >&2
    exit 4
fi

semgrep --json --config "$RULES_DIR" "$TARGET" > "$OUT" 2>/dev/null
echo "$OUT"
