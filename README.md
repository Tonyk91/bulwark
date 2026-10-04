# Bulwark

Guardrails as code for a bank's AWS platform. Every Terraform change a
development team proposes is checked against the bank's rules before it can
be merged. A violation blocks the pull request and tells the developer what is
wrong, how to fix it and why the rule exists. A team that cannot comply yet
can file a time-boxed exception, which fails the pipeline again when it
expires.

The idea is a platform team that makes the safe way the easy way: developers
move fast, and governance is enforced by the pipeline instead of by review
meetings.

```
 developer PR ──> policy unit tests ──> bank guardrails (blocking) ──> merge
  (Terraform)       opa test, 26         conftest + exceptions
                                     └─> Checkov baseline (advisory)
                                          report ──> PR job summary (PowerShell)
```

## The rules

| ID | Rule | Why a bank cares |
|---|---|---|
| BANK-001 | Workloads run in EU regions only | Customer data stays in the EU/EEA |
| BANK-002 | Every resource has an `Owner` and a valid `DataClassification` | Audits and incident response need an accountable owner |
| BANK-003 | Every S3 bucket has a full public access block | One public bucket is a reportable breach |
| BANK-004 | Every S3 bucket declares server-side encryption | Encryption must be reviewable in code, not left to defaults |
| BANK-005 | Confidential/restricted buckets use KMS | Keys the bank controls, rotates and can revoke |
| BANK-006 | No `Allow` statements with wildcard actions | A compromised workload must not become a compromised account |
| BANK-007 | Queues declare encryption at rest | Messages may carry customer data |

Rules are written in Rego ([`policy/rules.rego`](policy/rules.rego)). Variables
are resolved, so `region = var.aws_region` is checked against the variable's
default. Classification comes from the resource's tags or from the provider's
`default_tags`.

## What the developer sees

A failing pull request gets a table in the job summary:

| Rule | Resource | Problem | How to fix |
|---|---|---|---|
| BANK-004 | `aws_s3_bucket.uploads` | bucket has no server-side encryption configuration | add aws_s3_bucket_server_side_encryption_configuration for this bucket |
| BANK-007 | `aws_sqs_queue.ingest` | queue does not declare encryption at rest | set sqs_managed_sse_enabled = true, or kms_master_key_id for confidential payloads |

No `CKV_AWS_18 failed`: the message is for the developer, not the platform
team.

## Exceptions

Sometimes a team has to ship before it can comply. In
[`exceptions/exceptions.yaml`](exceptions/exceptions.yaml):

```yaml
- rule: BANK-005
  resource: aws_s3_bucket.uploads
  owner: team-docflow
  reason: Shared KMS key for the ingestion domain is not provisioned yet ...
  ticket: RISK-2041
  expires: "2026-12-31"
```

The pipeline enforces the process, not just the rules:

- An exception needs all six fields. A missing ticket or owner fails the build.
- It must expire within 180 days, so nothing is waived forever.
- When it expires, the original violation blocks again, plus a `BANK-EXC`
  finding saying the exception lapsed.
- A waived violation still shows up in the report as an active exception, with
  ticket and expiry date, so it stays visible.
- An exception waives one rule on one resource. "KMS not ready yet" (BANK-005)
  cannot waive "no encryption at all" (BANK-004). That is why they are two
  rules: the tests caught that a single combined rule let the exception
  cover both.

## Tried on a real workload

The workload in [`workloads/docflow`](workloads/docflow) is the Terraform from
DocFlow, my own event-driven ingestion pipeline (S3 → SQS → Lambda). I built it
security-first: public access blocked, TLS-only bucket policy, scoped queue
policy, dead-letter queue.

It still failed **9 of the bank checks** on the first run
([`docs/docflow-before.txt`](docs/docflow-before.txt)): no owner or
classification tags, no declared bucket encryption, queues relying on implicit
encryption. These are exactly the gaps that look fine in review and surface in
an audit. After fixing them, one finding remains (BANK-005: confidential data
on SSE-S3 instead of KMS), carried by a dated exception.

## Design decisions

- **Fail closed.** If conftest crashes or writes no results, the report step
  exits non-zero. An early version printed "passed" on empty input; a guardrail
  that fails open is worse than none.
- **The policies are tested like code.** 26 unit tests in
  [`policy/*_test.rego`](policy/) cover every rule in both directions (caught
  and allowed), plus each way an exception can be invalid. Time is mocked, so
  expiry tests are deterministic.
- **Bank rules block, the vendor baseline advises.** Checkov runs alongside
  with hundreds of generic checks but does not block; the bank's own rules are
  few, explained and owned.
- **Same checks everywhere.** `make check` locally, GitHub Actions
  ([`guardrails.yml`](.github/workflows/guardrails.yml)) and GitLab CI
  ([`.gitlab-ci.yml`](.gitlab-ci.yml)) run the same commands.

## Limits, honestly

- **Static analysis of HCL.** The rules read the Terraform source, which
  needs no cloud credentials and runs in seconds. Values only known at plan
  time (e.g. computed ARNs, module outputs) are not resolved. The next step is
  to run the same Rego against `terraform show -json` of a real plan.
- **Pre-deployment only.** Nothing here catches someone changing a bucket by
  hand in the console. The next step is the runtime layer: AWS Config rules
  for the same IDs, with drift metrics in Prometheus/Grafana.
- **The GitLab pipeline has not been run.** It mirrors the GitHub workflow,
  which does run on every push.
- **One cloud.** The rule IDs are cloud-neutral on purpose; Azure equivalents
  (Azure Policy) are not written.

## Run it

Requires [OPA](https://www.openpolicyagent.org/), [conftest](https://www.conftest.dev/)
and PowerShell 7.

```sh
make test     # 26 policy unit tests
make check    # check workloads/docflow, exits non-zero on blocking findings
make report   # same, rendered as the Markdown report
make check WORKLOAD=path/to/your/terraform
```
