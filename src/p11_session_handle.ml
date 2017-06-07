type t = P11_ulong.t
[@@deriving eq,yojson]
let to_string = Unsigned.ULong.to_string
let hash x = Unsigned.ULong.to_int x
