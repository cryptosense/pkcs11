type t = Pkcs11.CK_SESSION_HANDLE.t
[@@deriving eq,yojson]
val to_string: t -> string
val hash: t -> int
