output "uploads_bucket" {
  description = "S3 bucket for document uploads"
  value       = aws_s3_bucket.uploads.id
}

output "ingest_queue_url" {
  description = "SQS queue receiving S3 upload notifications"
  value       = aws_sqs_queue.ingest.url
}

output "ingest_dlq_url" {
  description = "Dead-letter queue for failed ingest messages"
  value       = aws_sqs_queue.ingest_dlq.url
}
