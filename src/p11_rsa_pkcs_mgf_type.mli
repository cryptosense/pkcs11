type t = Pkcs11_CK_ULONG.t
[@@deriving ord,yojson]

val _CKG_MGF1_SHA1 : t
val _CKG_MGF1_SHA256 : t
val _CKG_MGF1_SHA384 : t
val _CKG_MGF1_SHA512 : t
val _CKG_MGF1_SHA224 : t

val to_string : t -> string

val of_string : string -> t
