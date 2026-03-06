import os
import yaml
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

PROMPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "prompts")

def load_yaml_template(relative_path: str) -> str:
    """Load a YAML template file and return the system_prompt_template."""
    full_path = os.path.join(PROMPTS_DIR, relative_path)
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Template not found: {full_path}")
    
    with open(full_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    return data.get('system_prompt_template', '')

def get_hunter_templates_for_language(language: str) -> Dict[str, Any]:
    """Get all hunter templates for a specific language."""
    hunters = {}
    hunters_dir = os.path.join(PROMPTS_DIR, "hunters", language)
    
    if not os.path.exists(hunters_dir):
        logger.warning(f"No hunters directory for language: {language}")
        return hunters
    
    for filename in os.listdir(hunters_dir):
        if filename.endswith('.yaml'):
            template_path = os.path.join("hunters", language, filename)
            try:
                full_path = os.path.join(PROMPTS_DIR, template_path)
                with open(full_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                hunter_name = data.get('role', filename[:-5])
                hunters[hunter_name] = {
                    'template': data.get('system_prompt_template', ''),
                    'cwe_profile': data.get('cwe_profile', ''),
                    'description': data.get('description', '')
                }
            except Exception as e:
                logger.error(f"Failed to load hunter template {filename}: {e}")
    
    return hunters

def load_hunter_registry() -> Dict[str, Any]:
    """Load the hunter registry configuration."""
    registry_path = os.path.join(PROMPTS_DIR, "hunters.yaml")
    if not os.path.exists(registry_path):
        return {}
    
    with open(registry_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

COORDINATOR_PROMPT_TEMPLATE = load_yaml_template("core/coordinator.yaml")
REVERSE_TRACER_PROMPT_TEMPLATE = load_yaml_template("core/reverse_tracer.yaml")
LOGIC_AUDITOR_PROMPT_TEMPLATE = load_yaml_template("core/logic_auditor.yaml")
RED_VALIDATOR_PROMPT_TEMPLATE = load_yaml_template("core/red_validator.yaml")
BLUE_VALIDATOR_PROMPT_TEMPLATE = load_yaml_template("core/blue_validator.yaml")
REPORT_GENERATOR_PROMPT_TEMPLATE = load_yaml_template("core/report_generator.yaml")
RETRY_PROMPT_TEMPLATE = load_yaml_template("core/retry.yaml")

def format_coordinator_prompt(payload_json: str) -> str:
    return COORDINATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_reverse_tracer_prompt(payload_json: str, dynamic_tracing_strategy: str = "") -> str:
    s = REVERSE_TRACER_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)
    s = s.replace("{dynamic_tracing_strategy}", dynamic_tracing_strategy or "使用标准逆向追踪方法")
    return s

def format_logic_auditor_prompt(payload_json: str) -> str:
    return LOGIC_AUDITOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_red_validator_prompt(payload_json: str) -> str:
    return RED_VALIDATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_blue_validator_prompt(payload_json: str) -> str:
    return BLUE_VALIDATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_report_generator_prompt(payload_json: str) -> str:
    return REPORT_GENERATOR_PROMPT_TEMPLATE.replace("{payload_json}", payload_json)

def format_hunter_prompt(template: str, hunter_name: str, payload_json: str) -> str:
    return template.replace("{hunter_name}", hunter_name).replace("{payload_json}", payload_json)

def format_retry_prompt(error_details: str, raw_output: str) -> str:
    return RETRY_PROMPT_TEMPLATE.replace("{error_details}", error_details).replace("{raw_output}", raw_output)
