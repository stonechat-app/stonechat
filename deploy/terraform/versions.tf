terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.2"
    }
  }
}

# Credentials come from Application Default Credentials:
# `gcloud auth application-default login` with an account that can manage
# Compute Engine in var.project.
provider "google" {
  project = var.project
  region  = var.region
  zone    = var.zone
}
