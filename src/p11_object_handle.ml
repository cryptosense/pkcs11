type t = Pkcs11.CK_OBJECT_HANDLE.t
[@@deriving eq,ord,show,yojson]

let to_string = Unsigned.ULong.to_string
