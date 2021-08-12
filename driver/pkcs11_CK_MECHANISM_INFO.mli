(** Information about a particular mechanism ([CK_MECHANISM_INFO]) *)

type _t

type t = _t Ctypes.structure

val make : P11_mechanism_info.t -> t

val view : t -> P11_mechanism_info.t

val ck_mechanism_info : t Ctypes.typ
