%% -------------------------------------------------------------------
%% uuid.erl - UUID implementation in Erlang
%%
%% @author Tomasz Jakub Rup <tomasz.rup@gmail.com>
%% @copyright 2011 Tomasz Jakub Rup
%% @doc UUID ([http://www.ietf.org/rfc/rfc4122.txt RFC4122]) implementation in Erlang.
%% @end
%%
%% The MIT license.
%%
%% Copyright (c) 2011 Tomasz Jakub Rup
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to
%% deal in the Software without restriction, including without limitation the
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
%% sell copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
%% IN THE SOFTWARE.
%%
%% -------------------------------------------------------------------
-module(uuid).
-author("Tomasz Jakub Rup <tomasz.rup@gmail.com>").

%% API
-export([validate/1]).
-export([v3/2, v4/0, v5/2, nil/0]).
-export([to_string/1]).
-export([ns_dns/0, ns_url/0, ns_oid/0, ns_x500/0]).

%%====================================================================
%% API
%%====================================================================

%% ------------------------------------------------------------------
%% @spec validate(UUID) -> match | nomatch
%%       UUID = list() | binary() | integer()
%% @doc Validate a UUID.
%% @end
%% ------------------------------------------------------------------
validate(UUID) when is_list(UUID) ->
	re:run(UUID, "^\{?[0-9a-f]{8}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?[0-9a-f]{12}\}?$", [{capture, none}]);
validate(<<UUID:128>>) ->
	validate(to_string(UUID));
validate(_) ->
	nomatch.

%% ------------------------------------------------------------------
%% @spec v3(Namespace, Name) -> binary()
%%       Namespace = binary()
%%       Name = binary() | list()
%% @doc Get a MD5 name based UUID (RFC4122 Version 3).
%% @end
%% ------------------------------------------------------------------
v3(Namespace, Name) when is_binary(Namespace) ->
	crypto:start(),
	<<TimeLow:32, TimeMid:16, _:4, TimeHigh:12, _:2, ClkSeqHi:6, ClkSeqLow:8, Node:48>> = crypto:md5(list_to_binary([Namespace, Name])),
	gen_binary(TimeLow, TimeMid, TimeHigh, 3, 2, ClkSeqHi, ClkSeqLow, Node).

%% ------------------------------------------------------------------
%% @spec v4() -> binary()
%% @doc Get a (pseudo) random UUID (RFC4122 Version 4).
%% @end
%% ------------------------------------------------------------------
v4() ->
	gen_binary(rand(32), rand(16), rand(12), 4, 2, rand(6), rand(8), rand(48)).

%% ------------------------------------------------------------------
%% @spec v5(Namespace, Name) -> binary()
%%       Namespace = binary()
%%       Name = binary() | list()
%% @doc Get a SHA-1 name based UUID (RFC4122 Version 5).
%% @end
%% ------------------------------------------------------------------
v5(Namespace, Name) when is_binary(Namespace) ->
	crypto:start(),
	<<TimeLow:32, TimeMid:16, _:4, TimeHigh:12, _:2, ClkSeqHi:6, ClkSeqLow:8, Node:48, _:32>> = crypto:sha(list_to_binary([Namespace, Name])),
	gen_binary(TimeLow, TimeMid, TimeHigh, 5, 2, ClkSeqHi, ClkSeqLow, Node).

%% ------------------------------------------------------------------
%% @spec nil() -> binary()
%% @doc Get the RFC4122 Nil UUID.
%% @end
%% ------------------------------------------------------------------
nil() ->
	<<0:128>>.

%% ------------------------------------------------------------------
%% @spec to_string(UUID) -> String
%%       UUID = list() | binary() | integer()
%%       String = list()
%% @doc Format the UUID into string representation.
%% @end
%% ------------------------------------------------------------------
to_string(UUID) when is_list(UUID) ->
	lists:flatten(io_lib:format("~8.16.0b-~4.16.0b-~4.16.0b-~2.16.0b~2.16.0b-~12.16.0b", UUID));
to_string(UUID) when is_binary(UUID) ->
	to_string(unpack(UUID));
to_string(UUID) when is_integer(UUID) ->
	to_string(<<UUID:128>>).

%% ------------------------------------------------------------------
%% @spec ns_dns() -> binary()
%% @doc Get the RFC4122 fully-qualified domain name namespace UUID.
%% @end
%% ------------------------------------------------------------------
ns_dns() ->
	gen_binary(1806153744, 40365, 465, 1, 2, 128, 180, 825973027016).

%% ------------------------------------------------------------------
%% @spec ns_url() -> binary()
%% @doc Get the RFC4122 URL namespace UUID.
%% @end
%% ------------------------------------------------------------------
ns_url() ->
	gen_binary(1806153745, 40365, 465, 1, 2, 128, 180, 825973027016).

%% ------------------------------------------------------------------
%% @spec ns_oid() -> binary()
%% @doc Get the RFC4122 ISO OID namespace UUID.
%% @end
%% ------------------------------------------------------------------
ns_oid() ->
	gen_binary(1806153746, 40365, 465, 1, 2, 128, 180, 825973027016).

%% ------------------------------------------------------------------
%% @spec ns_x500() -> binary()
%% @doc Get the RFC4122 X.500 DN namespace UUID.
%% @end
%% ------------------------------------------------------------------
ns_x500() ->
	gen_binary(1806153748, 40365, 465, 1, 2, 128, 180, 825973027016).

%%====================================================================
%% Internal functions
%%====================================================================

%% ------------------------------------------------------------------
%% ------------------------------------------------------------------
gen_binary(TimeLow, TimeMid, TimeHi, Version, Res, ClkSeqHi, ClkSeqLow, Node) ->
	<<TimeLow:32, TimeMid:16, Version:4, TimeHi:12, Res:2, ClkSeqHi:6, ClkSeqLow:8, Node:48>>.

%% ------------------------------------------------------------------
%% ------------------------------------------------------------------
rand(Res) ->
	random:uniform(round(math:pow(2, Res)) - 1).

%% ------------------------------------------------------------------
%% ------------------------------------------------------------------
unpack(<<TimeLow:32, TimeMid:16, TimeHighAndVersion:16, ClkSeqHiRes:8, ClkSeqLow:8, Node:48>>) ->
	[TimeLow, TimeMid, TimeHighAndVersion, ClkSeqHiRes, ClkSeqLow, Node];
unpack(UUID) when is_integer(UUID) ->
	unpack(<<UUID:128>>).
