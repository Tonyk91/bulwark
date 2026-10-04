# Helpers that turn conftest's combined HCL2 input into a flat view of the
# Terraform configuration: resources, data sources, variables and providers.
#
# conftest --combine gives: [{"path": "s3.tf", "contents": {...}}, ...]
package main

resources contains r if {
	some f in input
	some rtype, by_name in f.contents.resource
	some name, blocks in by_name
	some body in blocks
	r := {
		"type": rtype,
		"name": name,
		"addr": sprintf("%s.%s", [rtype, name]),
		"body": body,
		"path": f.path,
	}
}

data_sources contains d if {
	some f in input
	some dtype, by_name in f.contents.data
	some name, blocks in by_name
	some body in blocks
	d := {"type": dtype, "name": name, "addr": sprintf("data.%s.%s", [dtype, name]), "body": body}
}

aws_providers contains p if {
	some f in input
	some p in f.contents.provider.aws
}

variable_default(name) := v if {
	some f in input
	v := f.contents.variable[name][0]["default"]
}

# Resolves a literal "${var.x}" to the variable's default. Anything that
# cannot be resolved statically is returned unchanged.
resolve(v) := out if {
	is_string(v)
	m := regex.find_all_string_submatch_n(`^\$\{var\.([A-Za-z0-9_-]+)\}$`, v, 1)
	count(m) == 1
	out := variable_default(m[0][1])
} else := v

resources_of(rtype) := {r | some r in resources; r.type == rtype}

# True when `ref` (e.g. "${aws_s3_bucket.uploads.id}") points at resource r.
references(ref, r) if {
	is_string(ref)
	startswith(ref, sprintf("${%s.", [r.addr]))
}

default_tags := object.union_n([t |
	some p in aws_providers
	some dt in p.default_tags
	t := dt.tags
])

effective_tags(r) := object.union(default_tags, object.get(r.body, "tags", {}))

classification(r) := lower(resolve(effective_tags(r).DataClassification))
