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

# 默认排除目录：测试代码 / 教学反例 / 构建产物 / IDE 元数据 —— 这些不应判为漏洞。
# 与主引擎 src/semgrep_scanner.py 的 DEFAULT_EXCLUDE_GLOBS 保持同步。
# ⚠️ semgrep --exclude 不支持 ** globstar；用单层目录名即可匹配任意嵌套位置。
EXCLUDE_GLOBS=(
    # 测试代码（单元 / 集成 / e2e），漏洞模式多是断言用，不应判 sink
    "test" "it" "tests" "__tests__" "playwright"
    # WebGoat 风格的教学反例 / 安全示范目录
    "mitigation" "securepasswords"
    # 构建产物 / 第三方
    "target" "build" ".gradle" "node_modules" "dist" "out"
    # Maven Wrapper 启动器
    "wrapper"
    # IDE / 工具元数据
    ".idea" ".vscode"
)
EXCLUDE_ARGS=()
for g in "${EXCLUDE_GLOBS[@]}"; do
    EXCLUDE_ARGS+=(--exclude "$g")
done

semgrep --json --config "$RULES_DIR" "${EXCLUDE_ARGS[@]}" "$TARGET" > "$OUT" 2>/dev/null
echo "$OUT"
