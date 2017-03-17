type t = Pkcs11.CK_SESSION_HANDLE.t
[@@deriving yojson]
let to_string = Unsigned.ULong.to_string
let equal a b = Unsigned.ULong.compare a b = 0
let hash x = Unsigned.ULong.to_int x
