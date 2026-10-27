data "aws_caller_identity" "current" {}

locals {
  name       = "tessera-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
}

# ──────────────────────────────────────────────
# Key management
# One customer-managed key protects every store of
# cardholder data and every log written by Tessera.
# ──────────────────────────────────────────────

resource "aws_kms_key" "tessera" {
  description             = "Tessera CMK for PAN encryption, token vault, and logs"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "TokenizerUse"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.tokenizer.arn }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid       = "CloudWatchLogsUse"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:*tessera-${var.environment}*"
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "tessera" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.tessera.key_id
}

# ──────────────────────────────────────────────
# Token vault
# Stores token -> KMS-encrypted PAN, plus last four
# digits. No sensitive authentication data is stored.
# ──────────────────────────────────────────────

resource "aws_dynamodb_table" "token_vault" {
  name                        = "${local.name}-token-vault"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "token"
  deletion_protection_enabled = true

  attribute {
    name = "token"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.tessera.arn
  }
}

# ──────────────────────────────────────────────
# Tokenizer identity — least privilege
# ──────────────────────────────────────────────

resource "aws_iam_role" "tokenizer" {
  name = "${local.name}-tokenizer"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "tokenizer" {
  name = "${local.name}-tokenizer"
  role = aws_iam_role.tokenizer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "VaultReadWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = aws_dynamodb_table.token_vault.arn
      },
      {
        Sid      = "PanEncryption"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = aws_kms_key.tessera.arn
      },
      {
        Sid      = "OwnLogsOnly"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.tokenizer.arn}:*"
      },
      {
        Sid      = "Tracing"
        Effect   = "Allow"
        Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      }
    ]
  })
}

# ──────────────────────────────────────────────
# Tokenizer function
# ──────────────────────────────────────────────

data "archive_file" "tokenizer" {
  type        = "zip"
  source_file = "${path.module}/../src/handler.py"
  output_path = "${path.module}/build/tokenizer.zip"
}

resource "aws_cloudwatch_log_group" "tokenizer" {
  name              = "/aws/lambda/${local.name}-tokenizer"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.tessera.arn
}

resource "aws_lambda_function" "tokenizer" {
  function_name                  = "${local.name}-tokenizer"
  role                           = aws_iam_role.tokenizer.arn
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  handler                        = "handler.lambda_handler"
  filename                       = data.archive_file.tokenizer.output_path
  source_code_hash               = data.archive_file.tokenizer.output_base64sha256
  memory_size                    = 256
  timeout                        = 10
  reserved_concurrent_executions = var.lambda_reserved_concurrency
  kms_key_arn                    = aws_kms_key.tessera.arn

  environment {
    variables = {
      TABLE_NAME     = aws_dynamodb_table.token_vault.name
      KMS_KEY_ID     = aws_kms_key.tessera.arn
      TOKEN_TTL_DAYS = tostring(var.token_ttl_days)
    }
  }

  tracing_config {
    mode = "Active"
  }

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.tokenizer.name
  }

  depends_on = [aws_iam_role_policy.tokenizer]
}

# ──────────────────────────────────────────────
# API — HTTP API with IAM (SigV4) auth on every route
# ──────────────────────────────────────────────

resource "aws_apigatewayv2_api" "tessera" {
  name          = "${local.name}-api"
  protocol_type = "HTTP"
  description   = "Tessera card tokenization API"
}

resource "aws_apigatewayv2_integration" "tokenizer" {
  api_id                 = aws_apigatewayv2_api.tessera.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.tokenizer.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "tokenize" {
  api_id             = aws_apigatewayv2_api.tessera.id
  route_key          = "POST /v1/tokenize"
  authorization_type = "AWS_IAM"
  target             = "integrations/${aws_apigatewayv2_integration.tokenizer.id}"
}

resource "aws_apigatewayv2_route" "detokenize" {
  api_id             = aws_apigatewayv2_api.tessera.id
  route_key          = "POST /v1/detokenize"
  authorization_type = "AWS_IAM"
  target             = "integrations/${aws_apigatewayv2_integration.tokenizer.id}"
}

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${local.name}-api"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.tessera.arn
}

resource "aws_apigatewayv2_stage" "tessera" {
  api_id      = aws_apigatewayv2_api.tessera.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = var.api_throttle_rate_limit
    throttling_burst_limit = var.api_throttle_burst_limit
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      requestTime    = "$context.requestTime"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      sourceIp       = "$context.identity.sourceIp"
      callerArn      = "$context.identity.userArn"
      authError      = "$context.authorizer.error"
      integrationErr = "$context.integrationErrorMessage"
    })
  }
}

resource "aws_lambda_permission" "api_invoke" {
  statement_id  = "AllowTesseraApiInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tokenizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.tessera.execution_arn}/*/*/v1/*"
}

# ──────────────────────────────────────────────
# Monitoring
# ──────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "auth_failures" {
  alarm_name          = "${local.name}-api-4xx"
  alarm_description   = "Tessera API 4xx spike: possible failed authentication or probing of the CDE"
  namespace           = "AWS/ApiGateway"
  metric_name         = "4xx"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.auth_failure_alarm_threshold
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.security_alerts_topic_arn]

  dimensions = {
    ApiId = aws_apigatewayv2_api.tessera.id
    Stage = aws_apigatewayv2_stage.tessera.name
  }
}
