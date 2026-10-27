output "api_endpoint" {
  description = "Tessera API base URL (IAM SigV4 auth required on every route)"
  value       = aws_apigatewayv2_api.tessera.api_endpoint
}

output "token_vault_table" {
  description = "DynamoDB token vault table name"
  value       = aws_dynamodb_table.token_vault.name
}

output "kms_key_arn" {
  description = "Tessera customer-managed KMS key ARN"
  value       = aws_kms_key.tessera.arn
}

output "tokenizer_role_arn" {
  description = "Execution role ARN of the tokenizer Lambda"
  value       = aws_iam_role.tokenizer.arn
}
