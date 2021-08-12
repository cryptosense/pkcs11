type t = string [@@deriving eq, ord, show, yojson]

val normalize : t -> t
