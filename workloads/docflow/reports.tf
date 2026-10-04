# Monthly ingestion reports for the business side.
resource "aws_s3_bucket" "reports" {
  bucket = "${var.project}-reports-${data.aws_caller_identity.current.account_id}"
}

data "aws_iam_policy_document" "report_writer" {
  statement {
    sid       = "WriteReports"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
  }
}
