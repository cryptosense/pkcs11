(** Version numbers used in several places ([CK_VERSION]) *)
type t

type u =
    {
      major: int;             (* byte sized *)
      minor: int;             (* byte sized *)
    }

val make: u -> t
val view: t -> u

val to_string: u -> string

val ck_version : t Ctypes.typ
