%% -------------------------------------------------------------------
%% uuid.erl - UUID implementation in Erlang
%%
%% @author Tomasz Jakub Rup <tomasz.rup@gmail.com>
%% @copyright 2011 Tomasz Jakub Rup
%% @see RFC 4211
%% @doc UUID implementation in Erlang.
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
-export([v4/0]).
-export([to_string/1, to_binary/1]).
-export([ns_nil/0, ns_dns/0, ns_url/0, ns_iso_oid/0, ns_x500_dn/0]).

%%====================================================================
%% API
%%====================================================================

%% ------------------------------------------------------------------
%% ------------------------------------------------------------------
validate(UUID) when is_list(UUID) ->
	re:run(UUID, "^\{?[0-9a-f]{8}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?[0-9a-f]{4}\-?[0-9a-f]{12}\}?$", [{capture, none}]);
validate(<<UUID:128>>) ->
	validate(to_string(UUID));
validate(_) ->
	nomatch.

%% ------------------------------------------------------------------
%% ------------------------------------------------------------------
v4() ->
	to_string(gen_binary(rand(32), rand(16), rand(12), 4, 2, rand(6), rand(8), rand(48))).

%% ------------------------------------------------------------------
%% ------------------------------------------------------------------
to_string(UUID) when is_list(UUID) ->
	lists:flatten(io_lib:format("~8.16.0b-~4.16.0b-~4.16.0b-~2.16.0b~2.16.0b-~12.16.0b", UUID));
to_string(UUID) when is_binary(UUID) ->
	to_string(unpack(UUID));
to_string(UUID) when is_integer(UUID) ->
	to_string(<<UUID:128>>).

%% ------------------------------------------------------------------
%% ------------------------------------------------------------------
to_binary(UUID) when is_integer(UUID) ->
	<<UUID:128>>.

%% ------------------------------------------------------------------
%% @doc Get the RFC4122 Nil UUID.
%% @end
%% ------------------------------------------------------------------
ns_nil() ->
	"00000000-0000-0000-0000-000000000000".

%% ------------------------------------------------------------------
%% @doc Get the RFC4122 DNS namespace UUID.
%% @end
%% ------------------------------------------------------------------
ns_dns() ->
	"6ba7b810-9dad-11d1-80b4-00c04fd430c8".

%% ------------------------------------------------------------------
%% @doc Get the RFC4122 URL namespace UUID.
%% @end
%% ------------------------------------------------------------------
ns_url() ->
	"6ba7b810-9dad-11d1-80b4-00c04fd430c8".

%% ------------------------------------------------------------------
%% @doc Get the RFC4122 OID namespace UUID.
%% @end
%% ------------------------------------------------------------------
ns_iso_oid() ->
	"6ba7b810-9dad-11d1-80b4-00c04fd430c8".

%% ------------------------------------------------------------------
%% @doc Get the RFC4122 X500 namespace UUID.
%% @end
%% ------------------------------------------------------------------
ns_x500_dn() ->
	"6ba7b810-9dad-11d1-80b4-00c04fd430c8".

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
