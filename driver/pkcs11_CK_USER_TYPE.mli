(** Types of Cryptoki users ([CK_USER_TYPE]) *)
type t = P11_ulong.t

val _CKU_SO : t

val _CKU_USER : t

val _CKU_CONTEXT_SPECIFIC : t

val make : P11_user_type.t -> t

val view : t -> P11_user_type.t

val typ : t Ctypes.typ
