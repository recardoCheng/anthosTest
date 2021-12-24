package envoy.authz

import input.attributes.request.http as http_request
import input.parsed_path as parsed_path

default allow = false

allow {
    action_allowed
}

token = {"payload": payload} {
    [_, encoded] := split(http_request.headers.authorization, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}

action_allowed {
  token.payload.sub == parsed_path[1]
}
