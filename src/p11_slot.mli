type t =
  | Index of int
  | Id of int
  | Description of string
  | Label of string
  [@@deriving yojson]

val default: t
val to_string: t -> string * string
