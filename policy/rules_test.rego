package main

# Fixtures mirror conftest's combined HCL2 input.

tf(contents) := [{"path": "main.tf", "contents": contents}]

provider(region, tags) := {"provider": {"aws": [{"region": region, "default_tags": [{"tags": tags}]}]}}

good_tags := {"Owner": "team-a", "DataClassification": "internal"}

bucket_with(extra) := object.union(
	{
		"provider": provider("eu-north-1", good_tags).provider,
		"resource": object.union(
			{
				"aws_s3_bucket": {"b": [{"bucket": "x"}]},
				"aws_s3_bucket_public_access_block": {"b": [{
					"bucket": "${aws_s3_bucket.b.id}",
					"block_public_acls": true,
					"block_public_policy": true,
					"ignore_public_acls": true,
					"restrict_public_buckets": true,
				}]},
				"aws_s3_bucket_server_side_encryption_configuration": {"b": [{
					"bucket": "${aws_s3_bucket.b.id}",
					"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
				}]},
			},
			extra,
		),
	},
	{},
)

rules_hit(inp) := {d.metadata.rule | some d in deny with input as inp}

# --- baseline ---------------------------------------------------------------

test_compliant_bucket_passes if {
	count(deny) == 0 with input as tf(bucket_with({}))
}

# --- BANK-001 data residency -------------------------------------------------

test_us_region_denied if {
	"BANK-001" in rules_hit(tf(provider("us-east-1", good_tags)))
}

test_region_resolved_from_variable if {
	inp := tf(object.union(
		provider("${var.region}", good_tags),
		{"variable": {"region": [{"default": "us-west-2"}]}},
	))
	"BANK-001" in rules_hit(inp)
}

test_eu_region_from_variable_allowed if {
	inp := tf(object.union(
		provider("${var.region}", good_tags),
		{"variable": {"region": [{"default": "eu-north-1"}]}},
	))
	not "BANK-001" in rules_hit(inp)
}

# --- BANK-002 ownership tags -------------------------------------------------

test_missing_owner_denied if {
	inp := tf(object.union(provider("eu-north-1", {"DataClassification": "internal"}), {"resource": {"aws_sqs_queue": {"q": [{"sqs_managed_sse_enabled": true}]}}}))
	"BANK-002" in rules_hit(inp)
}

test_resource_tags_satisfy_rule if {
	inp := tf(object.union(provider("eu-north-1", {}), {"resource": {"aws_sqs_queue": {"q": [{"sqs_managed_sse_enabled": true, "tags": good_tags}]}}}))
	count(deny) == 0 with input as inp
}

test_unknown_classification_denied if {
	inp := tf(object.union(provider("eu-north-1", {"Owner": "a", "DataClassification": "secret-ish"}), {"resource": {"aws_sqs_queue": {"q": [{"sqs_managed_sse_enabled": true}]}}}))
	"BANK-002" in rules_hit(inp)
}

# --- BANK-003 public access --------------------------------------------------

test_bucket_without_public_access_block_denied if {
	inp := tf({"provider": provider("eu-north-1", good_tags).provider, "resource": {"aws_s3_bucket": {"b": [{}]}}})
	"BANK-003" in rules_hit(inp)
}

test_partial_public_access_block_denied if {
	inp := tf(bucket_with({"aws_s3_bucket_public_access_block": {"b": [{
		"bucket": "${aws_s3_bucket.b.id}",
		"block_public_acls": true,
		"block_public_policy": false,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	}]}}))
	"BANK-003" in rules_hit(inp)
}

test_block_for_other_bucket_does_not_count if {
	inp := tf(bucket_with({"aws_s3_bucket_public_access_block": {"b": [{
		"bucket": "${aws_s3_bucket.other.id}",
		"block_public_acls": true,
		"block_public_policy": true,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	}]}}))
	"BANK-003" in rules_hit(inp)
}

# --- BANK-004/005 encryption -----------------------------------------------------

test_bucket_without_encryption_denied if {
	base := bucket_with({})
	no_sse := object.union(
		object.remove(base, ["resource"]),
		{"resource": object.remove(base.resource, ["aws_s3_bucket_server_side_encryption_configuration"])},
	)
	"BANK-004" in rules_hit(tf(no_sse))
}

test_confidential_bucket_requires_kms if {
	inp := tf(object.union(bucket_with({}), {"provider": provider("eu-north-1", {"Owner": "a", "DataClassification": "confidential"}).provider}))
	rules_hit(inp) == {"BANK-005"}
}

test_confidential_bucket_with_kms_passes if {
	inp := tf(object.union(
		bucket_with({"aws_s3_bucket_server_side_encryption_configuration": {"b": [{
			"bucket": "${aws_s3_bucket.b.id}",
			"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms", "kms_master_key_id": "${aws_kms_key.k.arn}"}]}],
		}]}}),
		{"provider": provider("eu-north-1", {"Owner": "a", "DataClassification": "confidential"}).provider},
	))
	count(deny) == 0 with input as inp
}

# --- BANK-006 wildcard IAM ---------------------------------------------------

iam_doc(statement) := tf({
	"provider": provider("eu-north-1", good_tags).provider,
	"data": {"aws_iam_policy_document": {"p": [{"statement": [statement]}]}},
})

test_wildcard_service_action_denied if {
	"BANK-006" in rules_hit(iam_doc({"effect": "Allow", "actions": ["s3:*"], "resources": ["*"]}))
}

test_star_action_with_default_effect_denied if {
	"BANK-006" in rules_hit(iam_doc({"actions": ["*"], "resources": ["*"]}))
}

test_wildcard_in_deny_statement_allowed if {
	not "BANK-006" in rules_hit(iam_doc({"effect": "Deny", "actions": ["s3:*"], "resources": ["*"]}))
}

test_specific_actions_allowed if {
	not "BANK-006" in rules_hit(iam_doc({"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["*"]}))
}

# --- BANK-007 queue encryption -----------------------------------------------

test_queue_without_encryption_denied if {
	inp := tf(object.union(provider("eu-north-1", good_tags), {"resource": {"aws_sqs_queue": {"q": [{}]}}}))
	"BANK-007" in rules_hit(inp)
}

test_queue_with_kms_passes if {
	inp := tf(object.union(provider("eu-north-1", good_tags), {"resource": {"aws_sqs_queue": {"q": [{"kms_master_key_id": "alias/x"}]}}}))
	not "BANK-007" in rules_hit(inp)
}
