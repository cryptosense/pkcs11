(** Parameter for [CKM_EXTRACT_KEY_FROM_KEY] ([CK_KEY_DERIVATION_STRING_DATA]) *)
type _t

type t = _t Ctypes.structure

type u = string

val make : u -> t

val view : t -> u

val t : t Ctypes.typ
