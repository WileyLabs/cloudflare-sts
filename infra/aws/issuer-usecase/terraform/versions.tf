terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }

  # Local state for now (never committed, see .gitignore). Switch to the shared remote backend before long-lived use.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}
