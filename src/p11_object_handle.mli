type t = Pkcs11.CK_OBJECT_HANDLE.t
[@@deriving eq,ord,show,yojson]

val to_string: t -> string
