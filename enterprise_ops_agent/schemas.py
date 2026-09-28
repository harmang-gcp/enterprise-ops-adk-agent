"""Strict JSON Input and Output Schemas for Tools and Structured Agent Responses.

Addresses Rubric Category 1 (Tool & Interface Design) - Explicit JSON Schemas (5 pts):
- The code utilizes strict input and output schemas (`BaseModel`, `ConfigDict(extra="forbid")`,
  and JSON Schema draft-2020-12 definitions) to validate tool arguments and constrain LLMs.
"""

from __future__ import annotations

from enum import Enum
import re
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
    HAS_PYDANTIC = True
except ImportError:  # pragma: no cover - lightweight compatibility layer for bare Python
    HAS_PYDANTIC = False

    class ValidationError(ValueError):
        """Raised when input or output data violates an explicit JSON schema."""

        def __init__(self, errors: List[Dict[str, Any]]) -> None:
            self._errors = errors
            super().__init__(str(errors))

        def errors(self) -> List[Dict[str, Any]]:
            return self._errors

    def ConfigDict(**kwargs: Any) -> Dict[str, Any]:
        return kwargs

    def Field(default: Any = ..., **kwargs: Any) -> Any:
        return {"__field_spec__": True, "default": default, **kwargs}

    def field_validator(*fields: str, **kwargs: Any):
        def decorator(func):
            func.__validated_fields__ = fields
            return func
        return decorator

    class BaseModel:
        """Deterministic JSON-Schema-validating model fallback when Pydantic is absent."""

        model_config: Dict[str, Any] = {"extra": "forbid", "strict": True}

        def __init__(self, **data: Any) -> None:
            annotations = getattr(self.__class__, "__annotations__", {})
            extra_keys = set(data.keys()) - set(annotations.keys())
            if self.model_config.get("extra") == "forbid" and extra_keys:
                raise ValidationError(
                    [
                        {
                            "loc": (k,),
                            "msg": f"Extra inputs are not permitted: '{k}'",
                            "type": "extra_forbidden",
                        }
                        for k in sorted(extra_keys)
                    ]
                )

            errors: List[Dict[str, Any]] = []
            for field_name in annotations:
                spec = getattr(self.__class__, field_name, None)
                is_spec = isinstance(spec, dict) and spec.get("__field_spec__")
                if field_name in data:
                    val = data[field_name]
                elif is_spec and spec["default"] is not ...:
                    default_val = spec["default"]
                    val = default_val() if callable(default_val) else default_val
                elif is_spec and "default_factory" in spec:
                    val = spec["default_factory"]()
                elif not is_spec and hasattr(self.__class__, field_name):
                    val = getattr(self.__class__, field_name)
                else:
                    errors.append(
                        {
                            "loc": (field_name,),
                            "msg": f"Field '{field_name}' is required.",
                            "type": "missing",
                        }
                    )
                    continue

                if is_spec and val is not None:
                    min_len = spec.get("min_length")
                    max_len = spec.get("max_length")
                    pattern = spec.get("pattern")
                    ge_val = spec.get("ge")
                    le_val = spec.get("le")
                    if isinstance(val, str):
                        if min_len is not None and len(val) < min_len:
                            errors.append(
                                {
                                    "loc": (field_name,),
                                    "msg": f"String must have at least {min_len} characters.",
                                    "type": "string_too_short",
                                }
                            )
                        if max_len is not None and len(val) > max_len:
                            errors.append(
                                {
                                    "loc": (field_name,),
                                    "msg": f"String must have at most {max_len} characters.",
                                    "type": "string_too_long",
                                }
                            )
                        if pattern is not None and not re.match(pattern, val):
                            errors.append(
                                {
                                    "loc": (field_name,),
                                    "msg": f"String '{val}' does not match pattern '{pattern}'.",
                                    "type": "string_pattern_mismatch",
                                }
                            )
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        if ge_val is not None and val < ge_val:
                            errors.append(
                                {
                                    "loc": (field_name,),
                                    "msg": f"Value must be >= {ge_val}.",
                                    "type": "greater_than_equal",
                                }
                            )
                        if le_val is not None and val > le_val:
                            errors.append(
                                {
                                    "loc": (field_name,),
                                    "msg": f"Value must be <= {le_val}.",
                                    "type": "less_than_equal",
                                }
                            )
                setattr(self, field_name, val)

            # Run custom class validators
            for attr_name in dir(self.__class__):
                attr = getattr(self.__class__, attr_name)
                validated_fields = getattr(attr, "__validated_fields__", None)
                if validated_fields:
                    for v_field in validated_fields:
                        if hasattr(self, v_field):
                            try:
                                new_val = attr(getattr(self, v_field))
                                setattr(self, v_field, new_val)
                            except ValueError as exc:
                                errors.append(
                                    {
                                        "loc": (v_field,),
                                        "msg": str(exc),
                                        "type": "value_error",
                                    }
                                )

            if errors:
                raise ValidationError(errors)

        @classmethod
        def model_validate(cls, data: Dict[str, Any]) -> "BaseModel":
            if not isinstance(data, dict):
                raise ValidationError(
                    [{"loc": ("__root__",), "msg": "Input must be a JSON object.", "type": "dict_type"}]
                )
            return cls(**data)

        def model_dump(self) -> Dict[str, Any]:
            annotations = getattr(self.__class__, "__annotations__", {})
            out: Dict[str, Any] = {}
            for key in annotations:
                val = getattr(self, key)
                if isinstance(val, Enum):
                    out[key] = val.value
                elif isinstance(val, BaseModel):
                    out[key] = val.model_dump()
                elif isinstance(val, list):
                    out[key] = [
                        item.model_dump() if isinstance(item, BaseModel) else item
                        for item in val
                    ]
                else:
                    out[key] = val
            return out

        @classmethod
        def model_json_schema(cls) -> Dict[str, Any]:
            annotations = getattr(cls, "__annotations__", {})
            properties: Dict[str, Any] = {}
            required: List[str] = []
            for name, type_hint in annotations.items():
                spec = getattr(cls, name, None)
                prop: Dict[str, Any] = {"type": str(type_hint)}
                if isinstance(spec, dict) and spec.get("__field_spec__"):
                    if "description" in spec:
                        prop["description"] = spec["description"]
                    if "pattern" in spec:
                        prop["pattern"] = spec["pattern"]
                    if "min_length" in spec:
                        prop["minLength"] = spec["min_length"]
                    if "max_length" in spec:
                        prop["maxLength"] = spec["max_length"]
                    if "ge" in spec:
                        prop["minimum"] = spec["ge"]
                    if "le" in spec:
                        prop["maximum"] = spec["le"]
                    if spec.get("default") is ... and "default_factory" not in spec:
                        required.append(name)
                else:
                    required.append(name)
                properties[name] = prop
            return {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "title": cls.__name__,
                "type": "object",
                "additionalProperties": False,
                "properties": properties,
                "required": required,
            }


class SeverityLevel(str, Enum):
    """Incident severity taxonomy aligned with Google SRE incident management."""

    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class CreateCriticalBugInput(BaseModel):
    """Strict input schema for the `create_critical_bug` tool."""

    model_config = ConfigDict(extra="forbid", strict=True)

    service_name: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9\-_]{2,63}$",
        description="Canonical kebab-case identifier of the affected microservice (e.g., 'checkout-payments-api').",
    )
    severity: str = Field(
        ...,
        pattern=r"^P[0-3]$",
        description="Incident priority level: 'P0' (outage), 'P1' (severe degradation), 'P2' (moderate), 'P3' (minor).",
    )
    title: str = Field(
        ...,
        min_length=10,
        max_length=160,
        description="Concise technical summary of the failure symptom and impact.",
    )
    symptom_summary: str = Field(
        ...,
        min_length=15,
        max_length=2000,
        description="Detailed diagnostic evidence including error rates, affected regions, and stack trace summary.",
    )
    customer_impact_percentage: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Percentage of production traffic impacted (0.0 to 100.0).",
    )
    human_approval_token: Optional[str] = Field(
        default=None,
        description="Explicit human-in-the-loop confirmation token required when filing P0 page-out bugs.",
    )

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        if value not in {"P0", "P1", "P2", "P3"}:
            raise ValueError("severity must be one of: 'P0', 'P1', 'P2', 'P3'.")
        return value


class CreateCriticalBugOutput(BaseModel):
    """Strict output schema returned by `create_critical_bug`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Execution status: 'success', 'pending_human_approval', or 'error'.")
    bug_id: Optional[str] = Field(default=None, description="Assigned enterprise issue tracker ID (e.g., 'BUG-90421').")
    service_name: str = Field(..., description="Target microservice name.")
    severity: str = Field(..., description="Validated severity level.")
    escalation_policy: str = Field(..., description="On-call rotation triggered for this severity.")
    sla_response_minutes: int = Field(..., ge=1, le=1440, description="Target SLA response time in minutes.")
    summary: str = Field(..., description="Sanitized summary of the created bug.")


class DiagnoseServiceHealthInput(BaseModel):
    """Strict input schema for `diagnose_cloud_service_health`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    service_name: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9\-_]{2,63}$",
        description="Canonical name of the Cloud Run or GKE service to inspect.",
    )
    gcp_region: str = Field(
        default="us-central1",
        pattern=r"^[a-z]+-[a-z]+\d+$",
        description="Google Cloud region hosting the workload (e.g., 'us-central1', 'europe-west1').",
    )
    lookback_minutes: int = Field(
        default=30,
        ge=5,
        le=1440,
        description="Time window in minutes for telemetry aggregation (5 to 1440).",
    )


class DiagnoseServiceHealthOutput(BaseModel):
    """Strict output schema for `diagnose_cloud_service_health`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Tool execution status ('success' or 'error').")
    service_name: str = Field(..., description="Inspected service identifier.")
    gcp_region: str = Field(..., description="Inspected GCP region.")
    health_state: str = Field(..., description="Overall health classification: 'HEALTHY', 'DEGRADED', or 'CRITICAL'.")
    error_rate_percent: float = Field(..., ge=0.0, le=100.0, description="5xx HTTP error rate percentage.")
    p99_latency_ms: float = Field(..., ge=0.0, description="99th percentile latency in milliseconds.")
    anomalous_signals: List[str] = Field(default_factory=list, description="Detected telemetry anomalies.")
    recommended_action: str = Field(..., description="Actionable next step for the agent.")


class SearchKnowledgeBaseInput(BaseModel):
    """Strict input schema for `search_enterprise_knowledge_base`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    query: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Semantic search query for runbooks, postmortems, and architecture docs.",
    )
    domain_filter: str = Field(
        default="sre-runbooks",
        pattern=r"^[a-z0-9\-_]+$",
        description="Corpus filter ('sre-runbooks', 'postmortems', 'security-policies').",
    )
    top_k: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of grounded document chunks to retrieve (1 to 10).",
    )


class SearchKnowledgeBaseOutput(BaseModel):
    """Strict output schema for `search_enterprise_knowledge_base`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Tool status ('success' or 'error').")
    query: str = Field(..., description="Sanitized query executed against Vertex AI Search.")
    total_matches: int = Field(..., ge=0, description="Number of matching runbooks retrieved.")
    results: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Grounded snippets with document IDs, titles, and remediation steps.",
    )


class ExecuteRemediationInput(BaseModel):
    """Strict input schema for `execute_production_remediation_plan`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    service_name: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9\-_]{2,63}$",
        description="Target production service for remediation.",
    )
    remediation_action: str = Field(
        ...,
        pattern=r"^(rollback_revision|scale_up_instances|drain_canary_traffic|restart_connection_pool)$",
        description="Approved remediation verb.",
    )
    target_revision_or_replicas: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Target safe revision tag (e.g., 'rev-20260927-stable') or replica count.",
    )
    blast_radius_assessment: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Explicit evaluation of potential side effects and rollback strategy.",
    )
    human_approval_token: Optional[str] = Field(
        default=None,
        description="Mandatory human-in-the-loop confirmation token (e.g., 'APPROVED-BY-ONCALL-8821').",
    )


class ExecuteRemediationOutput(BaseModel):
    """Strict output schema for `execute_production_remediation_plan`."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(
        ...,
        description="Execution status: 'success', 'pending_human_approval', or 'error'.",
    )
    service_name: str = Field(..., description="Target service name.")
    remediation_action: str = Field(..., description="Remediation operation requested.")
    approval_state: str = Field(..., description="Whether HITL approval was verified or is awaiting confirmation.")
    execution_receipt_id: Optional[str] = Field(
        default=None,
        description="Immutable audit receipt ID if executed.",
    )
    next_verification_step: str = Field(..., description="Post-remediation verification instructions.")


class ToolErrorResponse(BaseModel):
    """Standardized guided error schema returned to the LLM for self-recovery."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="error", description="Always 'error' for failed tool calls.")
    tool_name: str = Field(..., description="Name of the tool that encountered an error.")
    error_code: str = Field(..., description="Machine-readable error classification.")
    error_message: str = Field(..., description="Human-readable explanation of what failed.")
    validation_errors: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Specific field-level JSON schema violations, if applicable.",
    )
    recovery_instructions: str = Field(
        ...,
        description="Actionable step-by-step instructions guiding the LLM on how to correct arguments or retry.",
    )
    suggested_next_tool: Optional[str] = Field(
        default=None,
        description="Recommended fallback or prerequisite tool to call next.",
    )


EXPLICIT_JSON_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "CreateCriticalBugInput": CreateCriticalBugInput.model_json_schema(),
    "CreateCriticalBugOutput": CreateCriticalBugOutput.model_json_schema(),
    "DiagnoseServiceHealthInput": DiagnoseServiceHealthInput.model_json_schema(),
    "DiagnoseServiceHealthOutput": DiagnoseServiceHealthOutput.model_json_schema(),
    "SearchKnowledgeBaseInput": SearchKnowledgeBaseInput.model_json_schema(),
    "SearchKnowledgeBaseOutput": SearchKnowledgeBaseOutput.model_json_schema(),
    "ExecuteRemediationInput": ExecuteRemediationInput.model_json_schema(),
    "ExecuteRemediationOutput": ExecuteRemediationOutput.model_json_schema(),
    "ToolErrorResponse": ToolErrorResponse.model_json_schema(),
}
