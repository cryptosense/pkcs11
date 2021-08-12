(** MGF used in [CKM_RSA_PKCS_OAEP] ([CK_RSA_PKCS_MGF_TYPE]) *)
type t = P11_ulong.t [@@deriving ord]

val _CKG_MGF1_SHA1 : t

val _CKG_MGF1_SHA256 : t

val _CKG_MGF1_SHA384 : t

val _CKG_MGF1_SHA512 : t

val _CKG_MGF1_SHA224 : t

val to_string : t -> string

val of_string : string -> t

val typ : t Ctypes.typ
