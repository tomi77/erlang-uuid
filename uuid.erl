-module(uuid).
-export([validate/1]).

validate(String) ->
	re:run(String, "^\{?[0-9a-f]{8}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?[0-9a-f]{12}\}?$", [{capture, none}]).
