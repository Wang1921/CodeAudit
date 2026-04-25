#!/usr/bin/env bash
# security-audit-java skill 内置的 semgrep 薄封装。
# 用法：scan.sh <目标目录> [规则目录] [输出 JSON 路径]

set -euo pipefail

TARGET="${1:-}"
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_DIR="${2:-${SKILL_DIR}/rules}"
OUT="${3:-/tmp/semgrep-audit-$(date +%s).json}"

if [[ -z "$TARGET" ]]; then
    echo "用法：scan.sh <目标目录> [规则目录] [输出 JSON 路径]" >&2
    exit 2
fi
if ! command -v semgrep >/dev/null; then
    echo "未安装 semgrep。请执行：pip install semgrep" >&2
    exit 3
fi
if [[ ! -d "$RULES_DIR" ]]; then
    echo "找不到规则目录：$RULES_DIR" >&2
    echo "提示：请把 CodeAudit/semgrep_rules/custom/*.yaml 复制到 $RULES_DIR" >&2
    exit 4
fi

semgrep --json --config "$RULES_DIR" "$TARGET" > "$OUT" 2>/dev/null
echo "$OUT"
