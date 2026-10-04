# Bank guardrails for Terraform on AWS.
#
# Every rule produces a violation with an ID, the offending resource, what is
# wrong, how to fix it and why the rule exists. Messages are written for the
# developer reading a failed pipeline, not for the platform team.
package main

finding(rule, resource, problem, fix, why) := {
	"rule": rule,
	"resource": resource,
	"problem": problem,
	"fix": fix,
	"why": why,
}

allowed_classifications := {"public", "internal", "confidential", "restricted"}

# Classifications that require a customer-managed KMS key.
kms_required := {"confidential", "restricted"}

taggable_types := {
	"aws_s3_bucket", "aws_sqs_queue", "aws_lambda_function",
	"aws_dynamodb_table", "aws_kms_key", "aws_iam_role",
	"aws_sns_topic", "aws_cloudwatch_log_group",
}

# BANK-001 Data residency: workloads run in EU regions only.
findings contains v if {
	some p in aws_providers
	region := resolve(object.get(p, "region", "<unset>"))
	not startswith(region, "eu-")
	v := finding(
		"BANK-001", "provider.aws",
		sprintf("region %q is outside the EU", [region]),
		`set region to an EU region, e.g. "eu-north-1" (Stockholm)`,
		"customer data must stay within the EU/EEA",
	)
}

# BANK-002 Ownership: every taggable resource has an Owner and a valid
# DataClassification, either on the resource or via provider default_tags.
findings contains v if {
	some r in resources
	r.type in taggable_types
	some key in ["Owner", "DataClassification"]
	not effective_tags(r)[key]
	v := finding(
		"BANK-002", r.addr,
		sprintf("missing required tag %q", [key]),
		sprintf("add %q to the resource tags or to default_tags in the aws provider", [key]),
		"every resource needs an accountable owner and a data classification for audits and incident response",
	)
}

findings contains v if {
	some r in resources
	r.type in taggable_types
	effective_tags(r).DataClassification
	c := classification(r)
	not c in allowed_classifications
	v := finding(
		"BANK-002", r.addr,
		sprintf("DataClassification %q is not a known class", [c]),
		sprintf("use one of: %s", [concat(", ", sort(allowed_classifications))]),
		"classification decides which controls apply (encryption, access, retention)",
	)
}

# BANK-003 No public buckets: every bucket has a public access block with all
# four settings enabled.
public_access_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

fully_blocked(bucket) if {
	some pab in resources_of("aws_s3_bucket_public_access_block")
	references(pab.body.bucket, bucket)
	every flag in public_access_flags {
		pab.body[flag] == true
	}
}

findings contains v if {
	some b in resources_of("aws_s3_bucket")
	not fully_blocked(b)
	v := finding(
		"BANK-003", b.addr,
		"bucket is not fully protected against public access",
		sprintf("add aws_s3_bucket_public_access_block for this bucket with %s = true", [concat(", ", public_access_flags)]),
		"a single public bucket is a reportable data breach",
	)
}

# BANK-004 Encryption at rest: every bucket declares server-side encryption.
encryption_config(bucket) := cfg if {
	some cfg in resources_of("aws_s3_bucket_server_side_encryption_configuration")
	references(cfg.body.bucket, bucket)
}

sse_algorithm(cfg) := cfg.body.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm

findings contains v if {
	some b in resources_of("aws_s3_bucket")
	not encryption_config(b)
	v := finding(
		"BANK-004", b.addr,
		"bucket has no server-side encryption configuration",
		"add aws_s3_bucket_server_side_encryption_configuration for this bucket",
		"encryption must be declared in code so it is reviewable, not left to account defaults",
	)
}

# BANK-005 Customer-managed keys: confidential/restricted buckets use KMS.
# Separate from BANK-004 so an exception for "KMS not ready yet" can never
# waive "no encryption at all".
findings contains v if {
	some b in resources_of("aws_s3_bucket")
	classification(b) in kms_required
	cfg := encryption_config(b)
	sse_algorithm(cfg) != "aws:kms"
	v := finding(
		"BANK-005", b.addr,
		sprintf("%s data is encrypted with %q, not KMS", [classification(b), sse_algorithm(cfg)]),
		`set sse_algorithm = "aws:kms" and kms_master_key_id to a customer-managed key`,
		"confidential data needs keys the bank controls, rotates and can revoke",
	)
}

# BANK-006 Least privilege: no Allow statements with wildcard actions.
findings contains v if {
	some d in data_sources
	d.type == "aws_iam_policy_document"
	some s in d.body.statement
	object.get(s, "effect", "Allow") == "Allow"
	some action in s.actions
	wildcard_action(action)
	v := finding(
		"BANK-006", d.addr,
		sprintf("statement %q allows wildcard action %q", [object.get(s, "sid", "<no sid>"), action]),
		"list the specific actions the workload needs",
		"wildcard permissions turn a compromised workload into a compromised account",
	)
}

wildcard_action(a) if a == "*"

wildcard_action(a) if endswith(a, ":*")

# BANK-007 Queues declare their encryption explicitly.
findings contains v if {
	some q in resources_of("aws_sqs_queue")
	object.get(q.body, "kms_master_key_id", "") == ""
	object.get(q.body, "sqs_managed_sse_enabled", false) != true
	v := finding(
		"BANK-007", q.addr,
		"queue does not declare encryption at rest",
		"set sqs_managed_sse_enabled = true, or kms_master_key_id for confidential payloads",
		"messages may carry customer data; encryption must be visible in code review",
	)
}

# A violation blocks the pipeline unless a valid exception covers it.
deny contains result if {
	some v in findings
	not waived(v)
	result := {
		"msg": sprintf("[%s] %s: %s\n  fix: %s\n  why: %s", [v.rule, v.resource, v.problem, v.fix, v.why]),
		"metadata": v,
	}
}

# Visible in the report, but not blocking.
warn contains result if {
	some v in findings
	e := waiver(v)
	result := {
		"msg": sprintf("[%s] %s: waived until %s by %s (%s)", [v.rule, v.resource, e.expires, e.owner, e.ticket]),
		"metadata": object.union(v, {"waived_until": e.expires, "ticket": e.ticket}),
	}
}
