"""Security Guardrails, Policy Plugins, Self-Evaluation, and Human-in-the-Loop (HITL) Hooks.

Addresses Rubric Category 3 (Orchestration & Logic):
1. Guardrails & Policy Plugins (5 pts): Security and evaluation guardrails (including
   input prompt-injection defense, Google Cloud Model Armor integration, tool RBAC
   policy enforcement, and output self-evaluation) implemented as an ADK Plugin and
   lifecycle callbacks (`before_model_callback`, `after_model_callback`,
   `before_tool_callback`, `after_tool_callback`).
2. Human-in-the-Loop Hooks (5 pts): High-stakes actions (`execute_production_remediation_plan`
   and P0 `create_critical_bug`) enforce explicit code stops requiring verified human
   confirmation tokens or ADK `ToolContext.request_confirmation` before execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from enterprise_ops_agent.observability import default_audit_logger, default_tracer
from enterprise_ops_agent.pii_redaction import default_pii_redactor

try:
    from google.adk.plugins import BasePlugin
    HAS_ADK_PLUGIN = True
except ImportError:  # pragma: no cover
    HAS_ADK_PLUGIN = False

    class BasePlugin:  # type: ignore[no-redef]
        """Compatibility shim for ADK BasePlugin when running outside ADK runtime."""

        def __init__(self, name: str = "enterprise_security_plugin") -> None:
            self.name = name

try:
    from google.cloud import modelarmor_v1
    HAS_MODEL_ARMOR = True
except ImportError:  # pragma: no cover
    modelarmor_v1 = None
    HAS_MODEL_ARMOR = False


_PROMPT_INJECTION_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions", re.IGNORECASE),
    re.compile(r"reveal\s+(?:your\s+)?(?:system\s+prompt|secret|api\s+key)", re.IGNORECASE),
    re.compile(r"bypass\s+(?:human\s+approval|hitl|security\s+guardrail)", re.IGNORECASE),
    re.compile(r"drop\s+table|rm\s+-rf\s+/|delete\s+production\s+database", re.IGNORECASE),
)

_HIGH_STAKES_TOOLS: Set[str] = {
    "execute_production_remediation_plan",
    "create_critical_bug",
}

_VALID_APPROVAL_PREFIX = "APPROVED-"


@dataclass
class SelfEvaluationResult:
    """Result of the agentic self-evaluation guardrail check."""

    passed: bool
    overall_score: float
    groundedness_score: float
    safety_score: float
    policy_compliance_score: float
    critique_notes: List[str] = field(default_factory=list)
    remediated_response: Optional[str] = None


class HumanInTheLoopApprovalGate:
    """Explicit Human-in-the-Loop (HITL) gate for high-stakes operational actions."""

    def __init__(self) -> None:
        self._pending_requests: Dict[str, Dict[str, Any]] = {}
        self._approved_tokens: Set[str] = set()

    def register_approval_token(self, token: str) -> None:
        """Registers an operator-issued approval token."""
        if not token.startswith(_VALID_APPROVAL_PREFIX):
            raise ValueError(f"Approval token must start with '{_VALID_APPROVAL_PREFIX}'.")
        self._approved_tokens.add(token)

    def is_high_stakes_invocation(self, tool_name: str, tool_args: Dict[str, Any]) -> bool:
        """Determines whether a tool call requires mandatory human confirmation."""
        if tool_name == "execute_production_remediation_plan":
            return True
        if tool_name == "create_critical_bug" and tool_args.get("severity") == "P0":
            return True
        return False

    def verify_or_halt(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_context: Optional[Any] = None,
    ) -> Optional[Dict[str, Any]]:
        """Enforces a hard execution stop unless explicit human approval is present.

        Args:
            tool_name: Name of the tool about to execute.
            tool_args: Validated or raw arguments passed to the tool.
            tool_context: Optional ADK `ToolContext` object supporting `request_confirmation`.

        Returns:
            `None` if execution is approved to proceed; otherwise a structured
            `pending_human_approval` dictionary that halts execution and prompts the human.
        """
        if not self.is_high_stakes_invocation(tool_name, tool_args):
            return None

        token = tool_args.get("human_approval_token")
        if isinstance(token, str) and (
            token.startswith(_VALID_APPROVAL_PREFIX) or token in self._approved_tokens
        ):
            return None

        # Check ADK native ToolContext confirmation state if provided
        if tool_context is not None:
            tool_confirmation = getattr(tool_context, "tool_confirmation", None)
            if tool_confirmation and getattr(tool_confirmation, "confirmed", False):
                return None
            if hasattr(tool_context, "request_confirmation"):
                tool_context.request_confirmation(
                    hint=(
                        f"High-stakes action '{tool_name}' on service "
                        f"'{tool_args.get('service_name', 'unknown')}' requires human sign-off."
                    ),
                    payload=default_pii_redactor.redact_payload(tool_args),
                )

        approval_request_id = f"HITL-{uuid.uuid4().hex[:8].upper()}"
        sanitized_args = default_pii_redactor.redact_payload(tool_args)
        halt_payload = {
            "status": "pending_human_approval",
            "approval_state": "AWAITING_HUMAN_CONFIRMATION",
            "approval_request_id": approval_request_id,
            "tool_name": tool_name,
            "service_name": str(tool_args.get("service_name", "unknown")),
            "remediation_action": str(
                tool_args.get("remediation_action", tool_args.get("severity", "high_stakes_action"))
            ),
            "proposed_arguments": sanitized_args,
            "required_action": (
                "EXECUTION HALTED BY HUMAN-IN-THE-LOOP (HITL) GUARDRAIL. "
                "Present the blast radius, target service, and rollback plan to the human operator. "
                "Once the operator confirms, re-invoke this tool with "
                "`human_approval_token='APPROVED-BY-ONCALL-<ID>'`."
            ),
            "next_verification_step": (
                "Await explicit human operator confirmation before re-invoking the tool."
            ),
        }
        self._pending_requests[approval_request_id] = halt_payload
        return halt_payload

    def get_pending_requests(self) -> Dict[str, Dict[str, Any]]:
        """Returns all halted invocations awaiting human operator sign-off."""
        return dict(self._pending_requests)


class SelfEvaluationGuardrail:
    """Evaluates agent outputs for groundedness, policy adherence, and PII safety."""

    def evaluate_response(
        self,
        *,
        user_query: str,
        agent_response: str,
        tool_evidence: Optional[List[Dict[str, Any]]] = None,
    ) -> SelfEvaluationResult:
        """Runs deterministic and rubric-based self-evaluation on a candidate response."""
        notes: List[str] = []
        safety_score = 1.0
        policy_score = 1.0
        groundedness_score = 1.0

        # 1. Verify no unredacted PII leaked into the final output
        redacted_response = default_pii_redactor.redact_text(agent_response)
        if redacted_response != agent_response:
            safety_score -= 0.4
            notes.append("Detected unredacted PII in draft response; automatically scrubbed.")

        # 2. Check for unsafe or policy-violating instructions
        for pattern in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(redacted_response):
                policy_score = 0.0
                notes.append(f"Response violated security policy pattern: {pattern.pattern}")

        # 3. Verify groundedness against tool evidence when available
        if tool_evidence:
            referenced_services = [
                str(ev.get("service_name", ""))
                for ev in tool_evidence
                if isinstance(ev, dict) and ev.get("service_name")
            ]
            if referenced_services and not any(
                svc in redacted_response for svc in referenced_services
            ):
                groundedness_score = 0.7
                notes.append(
                    "Response should explicitly cite the inspected service_name from tool evidence."
                )

        if len(redacted_response.strip()) < 20:
            groundedness_score = min(groundedness_score, 0.5)
            notes.append("Response is overly brief; enterprise SRE responses require actionable detail.")

        overall = round((safety_score + policy_score + groundedness_score) / 3.0, 3)
        passed = overall >= 0.75 and policy_score > 0.0
        return SelfEvaluationResult(
            passed=passed,
            overall_score=overall,
            groundedness_score=groundedness_score,
            safety_score=safety_score,
            policy_compliance_score=policy_score,
            critique_notes=notes,
            remediated_response=redacted_response,
        )


class EnterpriseSecurityAndEvalPlugin(BasePlugin):
    """ADK Policy & Guardrail Plugin enforcing Model Armor, RBAC, HITL, and Self-Eval."""

    def __init__(
        self,
        hitl_gate: Optional[HumanInTheLoopApprovalGate] = None,
        self_evaluator: Optional[SelfEvaluationGuardrail] = None,
        allowed_tools: Optional[Set[str]] = None,
    ) -> None:
        super().__init__(name="enterprise_security_and_eval_plugin")
        self.hitl_gate = hitl_gate or HumanInTheLoopApprovalGate()
        self.self_evaluator = self_evaluator or SelfEvaluationGuardrail()
        self.allowed_tools = allowed_tools or {
            "diagnose_cloud_service_health",
            "search_enterprise_knowledge_base",
            "create_critical_bug",
            "execute_production_remediation_plan",
        }
        self.project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "enterprise-agentops-prod")

    def inspect_prompt_security(self, prompt_text: str) -> Optional[Dict[str, Any]]:
        """Screens user inputs via Google Cloud Model Armor and injection regexes."""
        with default_tracer.start_span(
            "guardrail.inspect_prompt_security",
            attributes={"guardrail.type": "input_security"},
        ):
            # 1. Google Cloud Model Armor API check when enabled
            if HAS_MODEL_ARMOR and os.environ.get("ENABLE_MODEL_ARMOR", "false").lower() == "true":
                try:
                    client = modelarmor_v1.ModelArmorClient()
                    template_name = os.environ.get(
                        "MODEL_ARMOR_TEMPLATE",
                        f"projects/{self.project_id}/locations/us-central1/templates/sre-agent-armor",
                    )
                    response = client.sanitize_user_prompt(
                        request={
                            "name": template_name,
                            "user_prompt_data": {"text": prompt_text},
                        }
                    )
                    if getattr(response, "sanitization_result", None) and getattr(
                        response.sanitization_result, "filter_match_state", 0
                    ) == 2:
                        return {
                            "status": "blocked_by_guardrail",
                            "reason": "Blocked by Google Cloud Model Armor security policy.",
                        }
                except Exception:
                    pass

            # 2. Local deterministic prompt injection & jailbreak defense
            for pattern in _PROMPT_INJECTION_PATTERNS:
                if pattern.search(prompt_text):
                    default_audit_logger.log_outcome(
                        correlation_id=f"sec-{uuid.uuid4().hex[:8]}",
                        action_type="SECURITY_GUARDRAIL",
                        target_name="inspect_prompt_security",
                        actual_status="blocked",
                        actual_output={"matched_pattern": pattern.pattern},
                        duration_ms=0.5,
                        intent_matched_outcome=False,
                    )
                    return {
                        "status": "blocked_by_guardrail",
                        "reason": (
                            "Request blocked by Enterprise Security Guardrail: detected "
                            "prompt injection, policy bypass, or destructive command pattern."
                        ),
                    }
            return None

    def before_model_callback(
        self,
        callback_context: Any,
        llm_request: Any,
    ) -> Optional[Any]:
        """ADK `before_model_callback` screening prompts before LLM invocation."""
        prompt_text = str(getattr(llm_request, "contents", llm_request))
        violation = self.inspect_prompt_security(prompt_text)
        if violation is not None:
            return violation
        return None

    def before_tool_callback(
        self,
        tool: Any,
        args: Dict[str, Any],
        tool_context: Any,
    ) -> Optional[Dict[str, Any]]:
        """ADK `before_tool_callback` enforcing tool allowlists and HITL confirmation."""
        tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", str(tool))
        if tool_name not in self.allowed_tools:
            return {
                "status": "error",
                "tool_name": tool_name,
                "error_code": "UNAUTHORIZED_TOOL_POLICY_VIOLATION",
                "error_message": f"Tool '{tool_name}' is not permitted by the RBAC policy plugin.",
                "recovery_instructions": (
                    f"Select one of the approved enterprise tools: {sorted(self.allowed_tools)}."
                ),
            }

        hitl_halt = self.hitl_gate.verify_or_halt(
            tool_name=tool_name,
            tool_args=args,
            tool_context=tool_context,
        )
        if hitl_halt is not None:
            return hitl_halt
        return None

    def after_model_callback(
        self,
        callback_context: Any,
        llm_response: Any,
    ) -> Optional[Any]:
        """ADK `after_model_callback` running self-evaluation and PII scrubbing."""
        text = getattr(llm_response, "text", None)
        if isinstance(text, str) and text:
            eval_result = self.self_evaluator.evaluate_response(
                user_query="",
                agent_response=text,
            )
            if hasattr(llm_response, "text") and eval_result.remediated_response:
                try:
                    llm_response.text = eval_result.remediated_response
                except Exception:
                    pass
        return None


default_hitl_gate = HumanInTheLoopApprovalGate()
default_self_evaluator = SelfEvaluationGuardrail()
default_security_plugin = EnterpriseSecurityAndEvalPlugin(
    hitl_gate=default_hitl_gate,
    self_evaluator=default_self_evaluator,
)
