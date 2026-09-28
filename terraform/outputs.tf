output "cloud_run_service_uri" {
  description = "HTTPS endpoint URL of the deployed ADK Agent Cloud Run service."
  value       = google_cloud_run_v2_service.adk_agent_service.uri
}

output "agent_service_account_email" {
  description = "Least-privilege IAM Service Account identity running the ADK agent."
  value       = google_service_account.adk_agent_runtime_sa.email
}

output "firestore_session_database" {
  description = "Firestore database name persisting cross-turn ADK session state."
  value       = google_firestore_database.agent_session_store.name
}

output "dlp_deidentify_template_id" {
  description = "Google Cloud DLP template ID used by PIIRedactionPipeline."
  value       = google_data_loss_prevention_deidentify_template.pii_redaction_template.id
}
