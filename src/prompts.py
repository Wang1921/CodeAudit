import os
import yaml
import logging
from typing import Optional

logger = logging.getLogger(__name__)

PROMPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts")

def load_yaml_template(relative_path: str) -> str:
    """Load a YAML template file and return system_prompt_template."""
    full_path = os.path.join(PROMPTS_DIR, relative_path)
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Template not found: {full_path}")
    
    with open(full_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    return data.get('system_prompt_template', '')

REVERSE_TRACER_PROMPT_TEMPLATE = load_yaml_template("core/reverse_tracer.yaml")
LOGIC_AUDITOR_PROMPT_TEMPLATE = load_yaml_template("core/logic_auditor.yaml")
RED_VALIDATOR_PROMPT_TEMPLATE = load_yaml_template("core/red_validator.yaml")
BLUE_VALIDATOR_PROMPT_TEMPLATE = load_yaml_template("core/blue_validator.yaml")
REPORT_GENERATOR_PROMPT_TEMPLATE = load_yaml_template("core/report_generator.yaml")
RETRY_PROMPT_TEMPLATE = load_yaml_template("core/retry.yaml")

def format_reverse_tracer_prompt(payload_json: str) -> str:
    return REVERSE_TRACER_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_logic_auditor_prompt(payload_json: str) -> str:
    return LOGIC_AUDITOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_red_validator_prompt(payload_json: str) -> str:
    return RED_VALIDATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_blue_validator_prompt(payload_json: str) -> str:
    return BLUE_VALIDATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_report_generator_prompt(payload_json: str) -> str:
    return REPORT_GENERATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_retry_prompt(error_details: str, raw_output: str) -> str:
    return RETRY_PROMPT_TEMPLATE.replace("{error_details}", error_details).replace("{raw_output}", raw_output)
