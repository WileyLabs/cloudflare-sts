terraform {
  required_version = ">= 1.9.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }

  # Local state for now (never committed, see .gitignore). Switch to a shared remote backend before long-lived use.
}

provider "google" {
  project = var.project_id
  region  = var.region
}
