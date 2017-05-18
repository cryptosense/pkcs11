(** Version numbers used in several places ([CK_VERSION]) *)
type t

val make : P11_version.t -> t

val view : t -> P11_version.t

val ck_version : t Ctypes.typ
