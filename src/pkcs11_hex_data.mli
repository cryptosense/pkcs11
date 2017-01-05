type t = string
[@@deriving ord,yojson]

val normalize : t -> t
