type t = Unsigned.ULong.t [@@deriving eq, ord, show, yojson]

val to_string : t -> string

val hash : t -> int
