package main

# "Today" for every test: 2026-10-04.
fixed_now := time.parse_ns("2006-01-02", "2026-10-04")

mock_now := fixed_now

# A bucket in a confidential account using SSE-S3: one BANK-005 finding.
kms_violation_input := tf(object.union(
	bucket_with({}),
	{"provider": provider("eu-north-1", {"Owner": "a", "DataClassification": "confidential"}).provider},
))

exc(expires) := {
	"rule": "BANK-005",
	"resource": "aws_s3_bucket.b",
	"owner": "team-a",
	"reason": "shared KMS key not provisioned yet",
	"ticket": "RISK-1",
	"expires": expires,
}

blocking_with(exceptions) := d if {
	d := deny with input as kms_violation_input
		with data.exceptions as exceptions
		with time.now_ns as mock_now
}

waived_with(exceptions) := w if {
	w := warn with input as kms_violation_input
		with data.exceptions as exceptions
		with time.now_ns as mock_now
}

test_valid_exception_waives_and_warns if {
	count(blocking_with([exc("2026-12-31")])) == 0
	count(waived_with([exc("2026-12-31")])) == 1
}

test_expired_exception_blocks if {
	d := blocking_with([exc("2026-10-01")])
	rules := {x.metadata.rule | some x in d}
	rules == {"BANK-005", "BANK-EXC"}
}

test_exception_beyond_180_days_blocks if {
	d := blocking_with([exc("2027-12-31")])
	rules := {x.metadata.rule | some x in d}
	rules == {"BANK-005", "BANK-EXC"}
}

test_exception_without_ticket_blocks if {
	e := object.remove(exc("2026-12-31"), ["ticket"])
	d := blocking_with([e])
	rules := {x.metadata.rule | some x in d}
	rules == {"BANK-005", "BANK-EXC"}
}

test_exception_with_bad_date_blocks if {
	d := blocking_with([exc("31/12/2026")])
	some x in d
	x.metadata.rule == "BANK-EXC"
	contains(x.msg, "not a YYYY-MM-DD date")
}

test_exception_for_other_resource_does_not_waive if {
	e := object.union(exc("2026-12-31"), {"resource": "aws_s3_bucket.other"})
	d := blocking_with([e])
	{x.metadata.rule | some x in d} == {"BANK-005"}
}

test_kms_exception_does_not_waive_missing_encryption if {
	base := bucket_with({})
	no_sse := object.union(
		object.remove(base, ["resource"]),
		{
			"provider": provider("eu-north-1", {"Owner": "a", "DataClassification": "confidential"}).provider,
			"resource": object.remove(base.resource, ["aws_s3_bucket_server_side_encryption_configuration"]),
		},
	)
	d := deny with input as tf(no_sse)
		with data.exceptions as [exc("2026-12-31")]
		with time.now_ns as mock_now
	"BANK-004" in {x.metadata.rule | some x in d}
}
