type t =
  | CKU_SO
  | CKU_USER
  | CKU_CONTEXT_SPECIFIC
  | CKU_CS_UNKNOWN of Pkcs11_CK_ULONG.t
[@@deriving eq,ord,yojson]

val to_string : t -> string

val of_string : string -> t
