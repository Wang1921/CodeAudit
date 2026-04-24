#!/usr/bin/env bash
# Install / sync the security-audit-java skill into a skill directory.
# Compatible with both OpenCode (.opencode/skills) and Claude Code (.claude/skills).
#
# Usage:
#   ./install.sh                    # defaults to ~/.opencode/skills (global)
#   ./install.sh --project          # installs to ./.opencode/skills (project-local)
#   ./install.sh --claude           # installs to ~/.claude/skills (global, Claude Code)
#   ./install.sh --path /custom     # custom target parent dir

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
        *) echo "unknown arg: $1" >&2; exit 2 ;;
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

echo "installing '${SKILL_NAME}' → ${TARGET}"
mkdir -p "$PARENT"

if [[ -L "$TARGET" || -d "$TARGET" ]]; then
    echo "  removing existing target first"
    rm -rf "$TARGET"
fi

# Copy instead of symlink: OpenCode skill resolver prefers real files, and
# rules/*.yaml need to be readable from skill cwd.
cp -r "$SCRIPT_DIR" "$TARGET"

# Make scripts executable
chmod +x "$TARGET"/scripts/*.sh "$TARGET"/scripts/*.py 2>/dev/null || true

echo "done."
echo "  SKILL.md: $TARGET/SKILL.md"
echo "  rules:    $TARGET/rules/ ($(find "$TARGET/rules" -name '*.yaml' | wc -l) yaml files)"
echo ""
echo "OpenCode: call with \`skill({ name: \"${SKILL_NAME}\" })\` from any agent."
echo "Claude Code: trigger on security-related Java audit requests."
