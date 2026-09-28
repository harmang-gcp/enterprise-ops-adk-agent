"""Enterprise SRE & Incident Response Multi-Agent System (Google ADK).

Exports `root_agent` and `app` for Google Agent Development Kit CLI commands:
- `adk web`
- `adk run enterprise_ops_agent`
- `adk eval enterprise_ops_agent eval/golden_dataset.json`
- `adk deploy cloud_run` / `adk deploy agent_engine`
"""

from enterprise_ops_agent.agent import (
    EnterpriseOpsOrchestrator,
    app,
    default_orchestrator,
    incident_resolution_pipeline,
    incident_triage_planner_agent,
    knowledge_retrieval_agent,
    parallel_diagnostic_gatherers,
    remediation_execution_agent,
    root_agent,
    self_evaluation_critic_agent,
    telemetry_diagnostics_agent,
)

__all__ = [
    "EnterpriseOpsOrchestrator",
    "app",
    "default_orchestrator",
    "incident_resolution_pipeline",
    "incident_triage_planner_agent",
    "knowledge_retrieval_agent",
    "parallel_diagnostic_gatherers",
    "remediation_execution_agent",
    "root_agent",
    "self_evaluation_critic_agent",
    "telemetry_diagnostics_agent",
]
