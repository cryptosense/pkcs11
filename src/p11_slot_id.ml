type t = Pkcs11.CK_SLOT_ID.t
[@@deriving eq,ord,show,yojson]

let to_string = Unsigned.ULong.to_string
let hash  = Unsigned.ULong.to_int
