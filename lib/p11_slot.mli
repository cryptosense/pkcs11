type t =
  | Index of int
  | Id of int
  | Description of string
  | Label of string
[@@deriving eq, ord, show, yojson]

val default : t

val to_string : t -> string * string
