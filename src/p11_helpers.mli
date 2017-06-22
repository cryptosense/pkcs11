val string_of_record:
  ?newlines:bool ->
  ?indent:string ->
  (string * string) list ->
  string

val strings_of_record:
  (string * string) list ->
  string list

(** Build a of_json function out of a of_string function.  The typename is used for the
    error message. *)
val of_json_string :
  typename:string ->
  (string -> 'a) ->
  Yojson.Safe.json ->
  ('a, string) Result.result

(** Remove trailing zeros and spaces, and quote the result.*)
val trim_and_quote : string -> string
