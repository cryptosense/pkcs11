type t = P11_ulong.t
[@@deriving eq,yojson]
val to_string: t -> string
val hash: t -> int
