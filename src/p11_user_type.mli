type t = Pkcs11.CK_USER_TYPE.u =
  | CKU_SO
  | CKU_USER
  | CKU_CONTEXT_SPECIFIC
  | CKU_CS_UNKNOWN of Unsigned.ULong.t
  [@@deriving eq,ord,yojson]

val to_string : t -> string
val of_string : string -> t
