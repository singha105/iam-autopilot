terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # State is deliberately local (infra/terraform/terraform.tfstate, gitignored):
  # an S3 state bucket is avoidable cost. See CLAUDE.md.
}
