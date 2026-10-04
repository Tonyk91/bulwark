variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "eu-north-1"
}

variable "project" {
  description = "Project name, used as prefix for resource names"
  type        = string
  default     = "docflow"
}
