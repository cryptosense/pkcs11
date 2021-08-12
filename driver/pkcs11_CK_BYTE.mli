(** Bytes ([CK_BYTE]) *)

type t = char

val zero : t

val one : t

val to_int : t -> int

val of_int : int -> t

val typ : t Ctypes.typ
