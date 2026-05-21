import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

PROMPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts")

# Skill guides 目录：按 agent 角色提供领域知识注入
_SKILL_DIR = Path(__file__).resolve().parent.parent / "skill" / "security-audit-java"
_GUIDES_DIR = _SKILL_DIR / "guides"


def load_agent_guide(agent_name: str) -> str:
    """加载 skill/guides/ 下对应 agent 的运行时指导文档。"""
    guide_path = _GUIDES_DIR / f"{agent_name}.md"
    if guide_path.exists():
        return guide_path.read_text(encoding="utf-8")
    logger.debug("Agent guide not found: %s", guide_path)
    return ""


def _load_yaml_doc(relative_path: str) -> dict[str, Any]:
    """Load the full YAML doc so callers can read any top-level key."""
    full_path = os.path.join(PROMPTS_DIR, relative_path)
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Template not found: {full_path}")
    with open(full_path, encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def load_yaml_template(relative_path: str) -> str:
    """Load a YAML template file and return system_prompt_template."""
    return _load_yaml_doc(relative_path).get('system_prompt_template', '')


_AGENT_FILES = {
    "ReverseTracer": "core/reverse_tracer.yaml",
    "LogicAuditor": "core/logic_auditor.yaml",
    "RedValidator": "core/red_validator.yaml",
    "BlueValidator": "core/blue_validator.yaml",
    # ReportGenerator 已改为纯 Python 字段映射（见 state_router._build_report_fields），不再是 LLM agent。
}

_AGENT_SCHEMAS: dict[str, dict | None] = {
    name: _load_yaml_doc(path).get("output_schema")
    for name, path in _AGENT_FILES.items()
}


def get_output_schema(agent_name: str) -> dict | None:
    """Return the JSON Schema for an Agent's output, or None if undefined."""
    return _AGENT_SCHEMAS.get(agent_name)


REVERSE_TRACER_PROMPT_TEMPLATE = load_yaml_template("core/reverse_tracer.yaml")
LOGIC_AUDITOR_PROMPT_TEMPLATE = load_yaml_template("core/logic_auditor.yaml")
RED_VALIDATOR_PROMPT_TEMPLATE = load_yaml_template("core/red_validator.yaml")
BLUE_VALIDATOR_PROMPT_TEMPLATE = load_yaml_template("core/blue_validator.yaml")
RETRY_PROMPT_TEMPLATE = load_yaml_template("core/retry.yaml")

def format_reverse_tracer_prompt(payload_json: str) -> str:
    prompt = REVERSE_TRACER_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)
    guide = load_agent_guide("reverse-tracer")
    if guide:
        prompt += f"\n\n## Agent 运行时指导\n{guide}"
    return prompt

def format_logic_auditor_prompt(payload_json: str) -> str:
    prompt = LOGIC_AUDITOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)
    guide = load_agent_guide("logic-auditor")
    if guide:
        prompt += f"\n\n## Agent 运行时指导\n{guide}"
    return prompt

def format_red_validator_prompt(payload_json: str) -> str:
    prompt = RED_VALIDATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)
    guide = load_agent_guide("red-validator")
    if guide:
        prompt += f"\n\n## Agent 运行时指导\n{guide}"
    return prompt

def format_blue_validator_prompt(payload_json: str) -> str:
    prompt = BLUE_VALIDATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)
    guide = load_agent_guide("blue-validator")
    if guide:
        prompt += f"\n\n## Agent 运行时指导\n{guide}"
    return prompt

def format_retry_prompt(error_details: str, raw_output: str) -> str:
    return RETRY_PROMPT_TEMPLATE.replace("{error_details}", error_details).replace("{raw_output}", raw_output)
