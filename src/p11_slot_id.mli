type t = Pkcs11.CK_SLOT_ID.t
[@@deriving eq,ord,show,yojson]
val to_string: t -> string
val hash : t -> int
