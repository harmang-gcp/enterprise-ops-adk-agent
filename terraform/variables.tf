variable "project_id" {
  description = "Google Cloud Project ID hosting the Enterprise Ops ADK Agent."
  type        = string
  default     = "enterprise-agentops-prod"
}

variable "region" {
  description = "Primary Google Cloud region for Vertex AI, Cloud Run, and Firestore."
  type        = string
  default     = "us-central1"
}

variable "agent_service_name" {
  description = "Canonical name of the Cloud Run ADK Agent service."
  type        = string
  default     = "enterprise-ops-adk-agent"
}

variable "container_image" {
  description = "Artifact Registry container image URI built via CI/CD."
  type        = string
  default     = "us-central1-docker.pkg.dev/enterprise-agentops-prod/agents/enterprise-ops-adk-agent:latest"
}
