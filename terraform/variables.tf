variable "aws_region" {
  description = "AWS region for the Tessera deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "production"
}

variable "security_alerts_topic_arn" {
  description = "ARN of the existing Security Engineering SNS topic that receives Tessera alarms"
  type        = string
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days. PCI DSS 10.5.1 requires at least 12 months."
  type        = number
  default     = 365

  validation {
    condition     = var.log_retention_days >= 365
    error_message = "Log retention must be at least 365 days (PCI DSS 10.5.1)."
  }
}

variable "token_ttl_days" {
  description = "Days a token and its encrypted PAN are retained before DynamoDB TTL expiry"
  type        = number
  default     = 365
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency cap for the tokenizer function"
  type        = number
  default     = 20
}

variable "api_throttle_rate_limit" {
  description = "Steady-state requests per second allowed on the Tessera API stage"
  type        = number
  default     = 50
}

variable "api_throttle_burst_limit" {
  description = "Burst request limit on the Tessera API stage"
  type        = number
  default     = 100
}

variable "auth_failure_alarm_threshold" {
  description = "Number of 4xx responses in five minutes that triggers the auth failure alarm"
  type        = number
  default     = 25
}
