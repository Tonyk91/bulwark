resource "aws_sqs_queue" "ingest_dlq" {
  name = "${var.project}-ingest-dlq"

  sqs_managed_sse_enabled = true

  # 14 days: maximum window to inspect and redrive failed documents
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "ingest" {
  name = "${var.project}-ingest"

  sqs_managed_sse_enabled = true

  # Must exceed the consuming Lambda's timeout (6x is the AWS recommendation)
  visibility_timeout_seconds = 300
  message_retention_seconds  = 345600

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.ingest_dlq.arn
    maxReceiveCount     = 3
  })
}

data "aws_iam_policy_document" "ingest_queue" {
  statement {
    sid       = "AllowS3Notification"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.ingest.arn]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.uploads.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "ingest" {
  queue_url = aws_sqs_queue.ingest.id
  policy    = data.aws_iam_policy_document.ingest_queue.json
}
