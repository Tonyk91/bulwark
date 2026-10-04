# Bulwark: bank guardrails for Terraform, run the same way locally and in CI.
WORKLOAD ?= workloads/docflow
PWSH     ?= pwsh

.PHONY: test check report fmt

## Unit tests for the policies themselves
test:
	opa test policy -v

## Check a workload against the guardrails (blocking findings exit non-zero)
check:
	conftest test --combine --parser hcl2 -p policy --data exceptions $(WORKLOAD)

## Same check, rendered as a Markdown report for the developer
report:
	conftest test --combine --parser hcl2 -p policy --data exceptions $(WORKLOAD) -o json > results.json || true
	$(PWSH) -NoProfile -File scripts/Write-PolicyReport.ps1 -ResultsPath results.json

fmt:
	opa fmt -w policy
	terraform fmt -recursive workloads
