provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project            = var.project
      ManagedBy          = "terraform"
      Owner              = "team-docflow"
      DataClassification = "confidential"
    }
  }
}
