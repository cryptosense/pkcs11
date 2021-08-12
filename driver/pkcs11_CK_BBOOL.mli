(** Booleans ([CK_BBOOL]) *)

type t = Pkcs11_CK_BYTE.t

val _CK_FALSE : t

val _CK_TRUE : t

val typ : t Ctypes.typ
