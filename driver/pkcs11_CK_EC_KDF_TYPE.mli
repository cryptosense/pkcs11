(** Parameters for EC key agreement schemes ([CK_EC_KDF_TYPE]) *)
type t

val make : P11_ec_kdf.t -> t

val view : t -> P11_ec_kdf.t

val t : t Ctypes.typ
