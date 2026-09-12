"""Registry of human-authored challenge templates."""
from typing import Dict, Type, List
from cyberlab.services.generator.template_base import BaseChallengeTemplate
from cyberlab.services.generator.templates.soc_auth_template import SocAuthTemplate
from cyberlab.services.generator.templates.phishing_dfir_template import PhishingDfirTemplate

TEMPLATE_REGISTRY: Dict[str, Type[BaseChallengeTemplate]] = {
    "soc-auth-investigation": SocAuthTemplate,
    "phishing-dfir": PhishingDfirTemplate,
}


def get_template(template_id: str) -> BaseChallengeTemplate:
    """Instantiate a challenge template by its ID."""
    if template_id not in TEMPLATE_REGISTRY:
        raise KeyError(f"Template '{template_id}' not found in template registry. Available: {list(TEMPLATE_REGISTRY.keys())}")
    return TEMPLATE_REGISTRY[template_id]()


def list_templates() -> List[Dict[str, str]]:
    """List all available templates with metadata."""
    res = []
    for tid, cls in TEMPLATE_REGISTRY.items():
        inst = cls()
        res.append({
            "id": tid,
            "title": inst.title,
            "category": inst.category,
            "difficulty": inst.difficulty,
            "competency_id": inst.competency_id,
        })
    return res
