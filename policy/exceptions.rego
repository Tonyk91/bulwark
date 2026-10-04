# Exceptions: a team may run with a known violation for a limited time, but
# only with an owner, a reason, a risk ticket and an expiry date. Expired or
# incomplete exceptions fail the pipeline themselves, so nothing is waived
# forever by accident.
package main

max_exception_days := 180

required_fields := ["rule", "resource", "owner", "reason", "ticket", "expires"]

default declared_exceptions := []

declared_exceptions := data.exceptions

day_ns := ((24 * 60) * 60) * 1000000000

expires_ns(e) := time.parse_ns("2006-01-02", e.expires)

complete(e) if {
	every f in required_fields {
		is_string(e[f])
		trim_space(e[f]) != ""
	}
}

valid_exception(e) if {
	complete(e)
	now := time.now_ns()
	expires_ns(e) > now
	expires_ns(e) <= now + (max_exception_days * day_ns)
}

waiver(v) := e if {
	some e in declared_exceptions
	e.rule == v.rule
	e.resource == v.resource
	valid_exception(e)
}

waived(v) if waiver(v)

# One entry per problem with an exception, keyed by its position in the file.
invalid_exceptions contains [i, "missing one of the required fields: rule, resource, owner, reason, ticket, expires"] if {
	some i, e in declared_exceptions
	not complete(e)
}

invalid_exceptions contains [i, sprintf("expires %q is not a YYYY-MM-DD date", [e.expires])] if {
	some i, e in declared_exceptions
	complete(e)
	not expires_ns(e)
}

invalid_exceptions contains [i, sprintf("expired on %s; fix the violation or renew the exception with risk sign-off", [e.expires])] if {
	some i, e in declared_exceptions
	complete(e)
	expires_ns(e) <= time.now_ns()
}

invalid_exceptions contains [i, sprintf("expires %s, more than %d days ahead; exceptions must be renewed at least twice a year", [e.expires, max_exception_days])] if {
	some i, e in declared_exceptions
	complete(e)
	expires_ns(e) > time.now_ns() + (max_exception_days * day_ns)
}

deny contains result if {
	some [i, problem] in invalid_exceptions
	label := object.get(declared_exceptions[i], "ticket", sprintf("#%d", [i]))
	result := {
		"msg": sprintf("[BANK-EXC] exception %s: %s", [label, problem]),
		"metadata": {"rule": "BANK-EXC", "resource": label, "problem": problem},
	}
}
