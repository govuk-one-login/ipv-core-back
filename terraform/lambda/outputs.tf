output "credential_issuer_iam_role_id" {
  description = "The ID of the IAM role used by the credential issuer lambda"
  value       = module.credential-issuer.iam_role_id
}