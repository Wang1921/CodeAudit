#!/usr/bin/env bash
# 把 security-audit-java skill 同步到目标 skill 目录。
# 同时兼容 OpenCode (.opencode/skills) 和 Claude Code (.claude/skills)。
#
# 用法：
#   ./install.sh                    # 默认装到 ~/.config/opencode/skills（OpenCode 全局）
#   ./install.sh --project          # 装到 ./.opencode/skills（项目级）
#   ./install.sh --claude           # 装到 ~/.claude/skills（Claude Code 全局）
#   ./install.sh --claude-project   # 装到 ./.claude/skills（Claude Code 项目级）
#   ./install.sh --path /custom     # 自定义父目录

set -euo pipefail

SKILL_NAME="security-audit-java"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="opencode-global"
CUSTOM_PATH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) MODE="opencode-project"; shift ;;
        --claude)  MODE="claude-global"; shift ;;
        --claude-project) MODE="claude-project"; shift ;;
        --path)    MODE="custom"; CUSTOM_PATH="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "${BASH_SOURCE[0]}" | head -15
            exit 0
            ;;
        *) echo "未知参数：$1" >&2; exit 2 ;;
    esac
done

case "$MODE" in
    opencode-global)   PARENT="${HOME}/.config/opencode/skills" ;;
    opencode-project)  PARENT="$(pwd)/.opencode/skills" ;;
    claude-global)     PARENT="${HOME}/.claude/skills" ;;
    claude-project)    PARENT="$(pwd)/.claude/skills" ;;
    custom)            PARENT="${CUSTOM_PATH%/}" ;;
esac

TARGET="${PARENT}/${SKILL_NAME}"

echo "正在安装 '${SKILL_NAME}' → ${TARGET}"
mkdir -p "$PARENT"

if [[ -L "$TARGET" || -d "$TARGET" ]]; then
    echo "  目标已存在，先删除"
    rm -rf "$TARGET"
fi

# 直接复制而非软链：OpenCode skill 解析器更倾向真实文件，且 rules/*.yaml 需要从 skill cwd 读取。
cp -r "$SCRIPT_DIR" "$TARGET"

# 给脚本加可执行位
chmod +x "$TARGET"/scripts/*.sh "$TARGET"/scripts/*.py 2>/dev/null || true

echo "安装完成。"
echo "  SKILL.md：$TARGET/SKILL.md"
echo "  规则：   $TARGET/rules/（共 $(find "$TARGET/rules" -name '*.yaml' | wc -l) 个 yaml 文件）"
echo ""
echo "OpenCode：在任意 agent 里调用 \`skill({ name: \"${SKILL_NAME}\" })\` 加载。"
echo "Claude Code：发起 Java 安全审计相关请求时会自动触发。"
