import logging
import os
from typing import Any

import yaml

logger = logging.getLogger(__name__)

PROMPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts")


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
    return REVERSE_TRACER_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_logic_auditor_prompt(payload_json: str) -> str:
    return LOGIC_AUDITOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_red_validator_prompt(payload_json: str) -> str:
    return RED_VALIDATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_blue_validator_prompt(payload_json: str) -> str:
    return BLUE_VALIDATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_retry_prompt(error_details: str, raw_output: str) -> str:
    return RETRY_PROMPT_TEMPLATE.replace("{error_details}", error_details).replace("{raw_output}", raw_output)
