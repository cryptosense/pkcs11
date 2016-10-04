(** Types of Cryptoki users ([CK_USER_TYPE]) *)
type t = Pkcs11_CK_ULONG.t

type u =
  | CKU_SO
  | CKU_USER
  | CKU_CONTEXT_SPECIFIC
  | CKU_CS_UNKNOWN of Unsigned.ULong.t

val _CKU_SO : t
val _CKU_USER : t
val _CKU_CONTEXT_SPECIFIC : t

val typ : t Ctypes.typ

include P11_sigs.PKCS with type t := t and type u := u
