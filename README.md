# Tessera

Card tokenization service for Meridian Capital, on AWS. Tessera must be compliant with PCI DSS.

- `docs/requirements.md` — application requirements
- `terraform/` — infrastructure
- `src/handler.py` — tokenizer Lambda

To deploy, copy `terraform/terraform.tfvars.example` to `terraform/terraform.tfvars`, set `security_alerts_topic_arn`, then run `terraform init` and `terraform apply` from `terraform/`.
