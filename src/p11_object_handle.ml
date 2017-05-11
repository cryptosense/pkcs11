type t = Pkcs11_CK_ULONG.t
[@@deriving eq,ord,show,yojson]

let to_string = Unsigned.ULong.to_string
