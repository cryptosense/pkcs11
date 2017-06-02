type t = Pkcs11_CK_SESSION_HANDLE.t
[@@deriving eq,yojson]
val to_string: t -> string
val hash: t -> int
