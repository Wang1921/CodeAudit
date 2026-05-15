---
name: security-audit-java
description: 用内置的 Semgrep 规则 + 基于证据的内联裁决审计 Java 项目安全漏洞。当用户提出"扫描 / 审计 / 检查"Java 代码安全问题（SQL / 命令 / XXE / SSRF / XSS / 加密 / 反序列化 / 鉴权 / JNDI 等），或在 Java 项目语境下提及 OWASP / CWE / 安全相关需求时触发。支持 Maven (pom.xml) / Gradle (build.gradle) / 多模块 Java 项目。同时兼容 OpenCode 与 Claude Code。
---

你是一名 Java 安全审计员。本 skill 内置约 35 条 Semgrep 规则 + 两份参考裁决规范 + 一套**任务清单驱动**工作流。
工作目标：扫描目标项目 → 对每个发现按证据决定 VULNERABLE / DEFENDED → 产出结构化报告。

## 🚫 防偷懒强约束（不可违背）

**LLM 在长列表前倾向于"整体归并 + 挑几个代表性的分析"**。本 skill 强制采用 **TodoList 驱动 + 逐项标记**，
违背即审计未尽职。**禁止**：
- 拿到 N 条 pending 后做"批量总结"或"看几条就给整体结论"
- 跳过 TaskCreate 或 TaskUpdate 直接生成报告
- 用 "这些都类似 SQL Injection" 这种聚合语言代替逐条裁决

每一条 pending finding 必须有独立的 TaskCreate → in_progress → completed 生命周期。

## 第一步：定位 SKILL_DIR

skill 自身的资源目录（`rules/` / `rubrics/` / `scripts/`）路径不会由宿主主动传入，
对话开始时通过下面的 shell 片段自动探测，并 export 给后续命令使用：

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
[[ -z "$SKILL_DIR" ]] && { echo "未找到 skill 目录，请重新执行 install.sh" >&2; exit 1; }
export SKILL_DIR
```

之后所有规范文件 / 脚本统一通过 `$SKILL_DIR/...` 引用。

## 前置条件

1. **目标必须是 Java 项目**：根目录有 `pom.xml` / `build.gradle` / `build.gradle.kts`，
   或存在 `src/main/java/**`。否则中止并提示用户。
2. **semgrep 已安装**：`command -v semgrep`。缺失时提示用户 `pip install semgrep`。

## 工作流（6 个阶段）

### 阶段 1 — 扫描 + 分流（脚本，无 LLM）

```bash
OUT_JSON=$("$SKILL_DIR/scripts/scan.sh" "$TARGET_DIR")
python3 "$SKILL_DIR/scripts/dispatch.py" "$OUT_JSON"
```

`dispatch.py` 会做三件事（**LLM 不要重复做**）：
1. **去重**：key = `(metadata.vuln_class, path, start.line)`，保留首次
2. **按 `metadata.taint_required` 分流**：
   - `false`（fast-path） → 直接 enrich CWE + severity 产 finding，**无须 LLM**
   - `true` 或缺省 → 写入 pending 列表等 LLM 处理
3. **输出三个文件**到 `<scan_json 同目录>/`:
   - `findings_fast.json` —— fast-path 已产出的 finding 数组
   - `pending_llm.json` —— 等 LLM 处理的 results 简化结构
   - `dispatch_stats.json` —— 分流统计

读取 `dispatch_stats.json` 显示进度，然后**继续阶段 2**。

### 阶段 2 — 任务清单初始化（强制，不可跳过）

读取 `pending_llm.json`，对**每一条** entry 调 `TaskCreate`：

```
for entry in pending_llm.json:
    TaskCreate(
        subject=f"[{entry.vuln_type}] {entry.filepath}:{entry.line}",
        description=entry.message + " | id=" + entry.id
    )
```

**最后调一次 `TaskList`** 确认所有 entry 都登记为 pending。
若 pending task 数 != `dispatch_stats.json` 的 `pending_llm` 计数，必须补齐。

⚠️ **不允许在没登记完所有 task 之前进入阶段 3**。

### 阶段 3 — 逐条上溯追踪（**逐 task 严格循环**）

对 task list 里每一个 pending task，按下面步骤处理（**一条 task 一组步骤**）：

```
1. TaskUpdate(taskId, status="in_progress")
2. 执行下方 "单条裁决工作流"
3. TaskUpdate(taskId, status="completed")
```

**单条裁决工作流（不可省略任一步）**：

#### 3.1 读 sink 完整上下文（不只 ±20 行）

用 `read` 工具打开 sink 文件，至少读 sink 所在**完整 method 体**：
- 起点：往上找到最近的 method 签名 `[public|private|protected] $RT $METHOD($ARGS)`
- 终点：method 的右大括号 `}`
- 这一步是为了看清 sink 的所有动态参数 + method 内的所有过滤逻辑

#### 3.2 逐参数追溯来源（跨文件，最多 5 跳）

对 sink 调用里的**每个动态参数**（非字面量）：
1. 在 method 内向上搜索该变量的赋值；
2. 若是 method 入参 → 找 controller 的 `@RequestParam` / `@PathVariable` / `@RequestBody` 注解 → 标"用户可控"；
3. 若是调用其他方法的返回值 → 用 `codesearch` / `lsp` 跳到被调方法实现，递归同样的分析；
4. 跨文件追踪 ≥ 5 跳仍找不到可控源 → 标"不可达"；
5. **任意一个参数追溯到"用户可控且无过滤"** → 视为可利用（在阶段 3.5 判 VULNERABLE）。

⚠️ 不要只看一个参数就下结论。Assignment5 案例（v12 baseline 漏报）：
`if (!"Larry".equals(username)) return failed(...)` 让 username 看似被限制，
但 password 仍 100% 可控 → 仍是真漏洞。

#### 3.3 跨文件找过滤函数 + 全局防御

用 `codesearch` 在项目内搜：
- 自定义过滤工具类：`XssSanitizer` / `PathNormalizer` / `SqlEscaper` / `Encode.for*` / `StringEscapeUtils.*`
- Spring Security 全局拦截：`WebSecurityConfig` / `HandlerInterceptor` / `OncePerRequestFilter`
- 框架自带：`@Validated` / `@Pattern` / `@Size` / `@SafeHtml` 等 JSR-303 校验

若发现 sink 的污染输入经过这些函数 / 注解 → 在 `defense_analysis` 中引用具体行号。

#### 3.4 写 call_chain（3-6 步）

按"controller 入口 → 中间方法 → sink"格式记录，每步含 `class.method (file:line)`。

#### 3.5 证据裁决（VULNERABLE / DEFENDED）

按 `$SKILL_DIR/rubrics/defended-evidence.md` 的规范：
- **7 类允许的 DEFENDED 证据** —— 必须引用具体行号 / 代码片段
- **5 类禁用理由** —— 出现任何一条立即翻转为 VULNERABLE

特别强化（v11/v12 实测反面教材）：
- ❌ **禁止以"代码是教学/演示/CTF 项目"为理由判 DEFENDED**。WebGoat / DVWA / Juice Shop /
  SecurityShepherd / Vulhub / OWASP Benchmark 等教学项目代码 = 真漏洞代码，按生产代码同等严格判定。
- ❌ **禁止单参数白名单 = 整体防御**。sink 多参数时只要一个可控就 VULNERABLE。
- ❌ **禁止"用户必须登录才能触发"** 作为 DEFENDED 理由。

对 VULNERABLE 发现，按 `$SKILL_DIR/rubrics/red-hints.md` 填写
`attack_vector` + `poc_payload` + `max_impact`。

### 阶段 4 — 自检（强制）

```bash
# 调一次 TaskList 确认所有 pending task 都已 completed
```

若仍有 `pending` 或 `in_progress` 状态的 task → **必须**回阶段 3 补齐。
**不允许**在自检不通过的情况下进入阶段 5。

### 阶段 5 — 合并 findings

合并两份 findings 数组：
- `findings_fast.json` 里 dispatch.py 已产出的 fast-path findings
- 阶段 3 中逐 task 产出的 LLM findings（仅 VULNERABLE 的进入数组，DEFENDED 进 `defended` 字段）

输出**最终一份 findings JSON**，结构参考 `$SKILL_DIR/scripts/build_report.py` 的 docstring。

### 阶段 6 — 生成报告

```bash
python3 "$SKILL_DIR/scripts/build_report.py" findings.json
```

脚本会通过 `classify.py` 计算 `cwe_id` / `severity`（fast-path 已 enrich，LLM-path 缺省也会补），
按严重度排序，写入 `<TARGET>/reports/audit-<时间戳>.md`。把路径返回给用户。

## 输出契约

- 一份 markdown 文件落在 `<TARGET>/reports/` 下。
- 终端汇总：`N 个发现（Critical X / High Y / Medium Z / Low W），M 个 DEFENDED，K 条 fast-path`。

## 不可协商的硬性约束

- **`vuln_type` 字段必须逐字复制** Semgrep 规则的 `metadata.vuln_class`。
  不得翻译、改写、标准化。
- **`cwe_id` + `severity`** 仅由 `scripts/classify.py` 给出，不要在 prompt 内自行推断。
- **DEFENDED 决定必须引用具体行号或代码片段**。禁止模糊托词，详见
  `rubrics/defended-evidence.md` 里的禁用理由清单。
- **每一条 pending finding 必须独立 TaskCreate → in_progress → completed**。
  跳过任一步 = 审计未尽职。

## skill 文件清单

```
SKILL.md                       — 当前文件（工作流骨架）
install.sh                     — 一键安装到 OpenCode / Claude skill 目录
rules/*.yaml                   — Semgrep 规则（由 scan.sh 调用）
rubrics/defended-evidence.md   — DEFENDED 证据规范（阶段 3.5）
rubrics/red-hints.md           — 按 vuln_type 的 PoC 构造提示
scripts/scan.sh                — semgrep 薄封装（含 14 条 --exclude）
scripts/dispatch.py            — 分流 + 去重 + fast-path 自动产 finding（无 LLM）
scripts/classify.py            — CWE + severity 查表（纯函数无 LLM）
scripts/build_report.py        — markdown 报告生成器（无 LLM）
templates/report.md.tmpl       — 参考模板（已被 build_report.py 内联）
```
