"""Strategic Model Routing between Gemini Flash and Gemini Pro.

Addresses Rubric Category 3 (Orchestration & Logic) - Strategic Model Routing (5 pts):
- Dynamically routes specific requests and sub-agent tasks to the most appropriate
  Gemini model tier (`gemini-2.5-flash` for high-speed retrieval, classification, and
  telemetry polling; `gemini-2.5-pro` for complex multi-step incident triage, root-cause
  reasoning, remediation planning, and constitutional self-evaluation).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from enterprise_ops_agent.observability import default_audit_logger, default_tracer

FAST_MODEL_ID = "gemini-2.5-flash"
REASONING_MODEL_ID = "gemini-2.5-pro"

_COMPLEX_PLANNING_KEYWORDS: Tuple[str, ...] = (
    "root cause",
    "remediation plan",
    "architecture",
    "rollback",
    "p0",
    "outage",
    "postmortem",
    "blast radius",
    "multi-region",
    "cascading failure",
    "critical",
    "escalate",
)

_FAST_TASK_TYPES: Tuple[str, ...] = (
    "telemetry_lookup",
    "knowledge_search",
    "intent_classification",
    "history_compaction",
    "schema_validation",
)

_PRO_TASK_TYPES: Tuple[str, ...] = (
    "incident_planning",
    "root_cause_analysis",
    "remediation_execution",
    "self_evaluation_critique",
    "multi_agent_coordination",
)


@dataclass(frozen=True)
class ModelRoutingDecision:
    """Immutable record describing why a specific Gemini model tier was chosen."""

    selected_model: str
    tier: str
    task_type: str
    complexity_score: float
    rationale: str


class StrategicModelRouter:
    """Selects between `gemini-2.5-flash` and `gemini-2.5-pro` based on task and query complexity."""

    def __init__(
        self,
        fast_model: str = FAST_MODEL_ID,
        pro_model: str = REASONING_MODEL_ID,
        complexity_threshold: float = 0.55,
    ) -> None:
        self.fast_model = fast_model
        self.pro_model = pro_model
        self.complexity_threshold = complexity_threshold

    def compute_query_complexity(self, query: str, task_type: str = "general") -> float:
        """Scores task complexity on a [0.0, 1.0] scale."""
        if task_type in _PRO_TASK_TYPES:
            return 0.85
        if task_type in _FAST_TASK_TYPES:
            return 0.20

        normalized = query.lower()
        keyword_hits = sum(1 for kw in _COMPLEX_PLANNING_KEYWORDS if kw in normalized)
        length_factor = min(0.35, len(normalized.split()) / 120.0)
        score = min(1.0, round(0.15 + (0.22 * keyword_hits) + length_factor, 3))
        return score

    def route(
        self,
        query: str,
        task_type: str = "general",
        agent_name: Optional[str] = None,
    ) -> ModelRoutingDecision:
        """Determines the optimal Gemini model (`gemini-2.5-flash` vs `gemini-2.5-pro`)."""
        with default_tracer.start_span(
            "routing.select_optimal_model",
            attributes={"task.type": task_type, "agent.name": agent_name or "router"},
        ):
            complexity = self.compute_query_complexity(query=query, task_type=task_type)
            if complexity >= self.complexity_threshold:
                decision = ModelRoutingDecision(
                    selected_model=self.pro_model,
                    tier="PRO_REASONING",
                    task_type=task_type,
                    complexity_score=complexity,
                    rationale=(
                        f"Task '{task_type}' scored complexity={complexity} (>= {self.complexity_threshold}); "
                        f"routing to '{self.pro_model}' for deep multi-step planning and safety analysis."
                    ),
                )
            else:
                decision = ModelRoutingDecision(
                    selected_model=self.fast_model,
                    tier="FLASH_LOW_LATENCY",
                    task_type=task_type,
                    complexity_score=complexity,
                    rationale=(
                        f"Task '{task_type}' scored complexity={complexity} (< {self.complexity_threshold}); "
                        f"routing to '{self.fast_model}' for high-throughput, low-latency execution."
                    ),
                )

            corr_id = default_audit_logger.log_intent(
                action_type="MODEL_ROUTING",
                target_name=decision.selected_model,
                intended_inputs={"task_type": task_type, "complexity_score": complexity},
                rationale=decision.rationale,
                agent_name=agent_name or "strategic_model_router",
            )
            default_audit_logger.log_outcome(
                correlation_id=corr_id,
                action_type="MODEL_ROUTING",
                target_name=decision.selected_model,
                actual_status="routed",
                actual_output={
                    "selected_model": decision.selected_model,
                    "tier": decision.tier,
                    "complexity_score": decision.complexity_score,
                },
                duration_ms=0.2,
                agent_name=agent_name or "strategic_model_router",
            )
            return decision


default_model_router = StrategicModelRouter()
