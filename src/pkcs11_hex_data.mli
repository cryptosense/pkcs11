type t = string
[@@deriving ord,yojson]

val normalize : t -> t

val typ : t Record.Type.t
[@@deprecated "Please use yojson functions directly"]
