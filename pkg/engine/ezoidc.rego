package ezoidc

import rego.v1

# regal ignore:constant-condition
allow.read(name) if false

# regal ignore:constant-condition
allow.internal(name) if false

# regal ignore:constant-condition
define.nil if false

issuers[key] := data.issuers[key]

claims[key] := input.claims[key]

params[key] := input.params[key]

read(name) := var.value.string if {
	some var in input.variables
	var.name == name
} else if {
	print($"warn: read: failed to read variable '{name}'")
	false
}

variables[var.name][field] := var[field] if {
	some var in input.variables
}

issuer := name if {
	some name
	issuers[name].issuer == input.claims.iss
}

subject := claims.sub

# Queries
_queries.allowed_variables[name] := _variable_scope(name) if {
	some name in data.variable_names
}

_variable_scope(name) := "read" if {
	allow.read(name)
} else := "internal" if {
	allow.internal(name)
}

_queries.variables_response contains object.union(vars, defs)[_] if {
	vars := {var.name: var |
		input.allow[name] == "read"
		var := variables[_]
		var.name == name
	}
	defs := {name: object.union(def, {"name": name}) |
		input.allow[name] == "read"
		def := define[name]
	}
}

# Utilities
fetch(options) := response if {
	headers := {"User-Agent": $"ezoidc/{data.version}"} # regal ignore:external-reference
	request := object.union({"method": "GET", "headers": headers}, options)
	response := _fetch_log_http_send(request)
}

_fetch_log_http_send(request) := response if {
	response := http.send(request)
	print($"debug: fetch: {request.method} {request.url}: {response.status_code}")
} else if {
	print($"warn: fetch failed: {request.method} {request.url}")
	false
}

github_app_jwt(options) := token if {
	iat := round(time.now_ns() / 1e9)
	exp := iat + (10 * 60)
	token := io.jwt.encode_sign(
		{"typ": "JWT", "alg": "RS256"},
		{"exp": exp, "iat": iat, "iss": options.app_id},
		crypto.x509.parse_rsa_private_key(options.private_key),
	)
} else if {
	print("warn: github.app.jwt: failed to sign app token")
	false
}

github_app_installation_token(options) := response.token if {
	url := $"https://api.github.com/app/installations/{options.installation_id}/access_tokens"
	body := object.get(options, "body", {})
	app_token := github_app_jwt(object.filter(options, ["app_id", "private_key"]))
	response := fetch({
		"url": url,
		"method": "POST",
		"headers": {"Authorization": $"Bearer {app_token}"},
		"body": body,
	}).body
} else if {
	print("warn: github.app.installation_token: failed to fetch installation token")
	false
}

cloudflare_r2_temporary_credentials(options) := response if {
	url := $"https://api.cloudflare.com/client/v4/accounts/{options.account_id}/r2/temp-access-credentials"
	defaults := {
		"bucket": object.get(options, "bucket", null),
		"parentAccessKeyId": object.get(options, "parent_access_key_id", null),
		"ttlSeconds": object.get(options, "ttl_seconds", 900),
		"permission": object.get(options, "permission", "object-read-only"),
		"objects": object.get(options, "objects", null),
		"prefixes": object.get(options, "prefixes", null),
	}
	body := {k: v | v := defaults[k]; v != null} # regal ignore:unused-output-variable
	response := fetch({
		"url": url,
		"method": "POST",
		"headers": {
			"Authorization": $"Bearer {options.token}",
			"Content-Type": "application/json",
		},
		"body": body,
	}).body
} else if {
	print("warn: cloudflare.r2.temporary_credentials: failed to fetch token")
	false
}
