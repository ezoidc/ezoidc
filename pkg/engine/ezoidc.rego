package ezoidc

import rego.v1

allow.read(name) if false

allow.internal(name) if false

define.nil if false

issuers[key] := data.issuers[key]

claims[key] := input.claims[key]

read(name) := value if {
	value := variables[name].value.string
} else if {
	print(sprintf("warn: read: failed to read variable '%s'", [name]))
	false
}

variables[var.name][field] := var[field] if {
	some var in input.variables
}

issuer := name if {
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

_queries.variables_response contains var if {
	vars := {var.name: var |
		input.allow[name] == "read"
		var := variables[_]
		var.name == name
	}
	defs := {name: object.union(def, {"name": name}) |
		input.allow[name] == "read"
		def := define[name]
	}
	var := object.union(vars, defs)[_]
}

# Utilities
fetch(options) := response if {
	request := object.union({
		"method": "GET",
		"headers": {
			"User-Agent": sprintf("ezoidc/%s", [data.version]),
		},
	}, options)
	response := _fetch_log_http_send(request)
}

_fetch_log_http_send(request) := response if {
	response := http.send(request)
	print(sprintf("debug: fetch: %s %s: %d", [request.method, request.url, response.status_code]))
} else if {
	print(sprintf("warn: fetch failed: %s %s", [request.method, request.url]))
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
	url := sprintf("https://api.github.com/app/installations/%v/access_tokens", [options.installation_id])
	body := object.get(options, "body", {})
	app_token := github_app_jwt(object.filter(options, ["app_id", "private_key"]))
	response := fetch({
		"url": url,
		"method": "POST",
		"headers": {"Authorization": concat(" ", ["Bearer", app_token])},
		"body": body,
	}).body
} else if {
	print("warn: github.app.installation_token: failed to fetch installation token")
	false
}

cloudflare_r2_temporary_credentials(options) := response if {
	url := sprintf("https://api.cloudflare.com/client/v4/accounts/%s/r2/temp-access-credentials", [options.account_id])
	defaults := {
		"bucket": object.get(options, "bucket", null),
		"parentAccessKeyId": object.get(options, "parent_access_key_id", null),
		"ttlSeconds": object.get(options, "ttl_seconds", 900),
		"permission": object.get(options, "permission", "object-read-only"),
		"objects": object.get(options, "objects", null),
		"prefixes": object.get(options, "prefixes", null),
	}
	body := {k: v | v := defaults[k]; v != null}
	response := fetch({
		"url": url,
		"method": "POST",
		"headers": {
			"Authorization": sprintf("Bearer %v", [options.token]),
			"Content-Type": "application/json",
		},
		"body": body,
	}).body
} else if {
	print("warn: cloudflare.r2.temporary_credentials: failed to fetch token")
	false
}
