type t =
  { major : int
  ; minor : int }
[@@deriving eq, ord, show, yojson]

val to_string : t -> string
