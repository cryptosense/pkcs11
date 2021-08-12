(** Driver information ([CK_INFO]) *)
type _t

type t = _t Ctypes.structure

val make : P11_info.t -> t

val view : t -> P11_info.t

val ck_info : t Ctypes.typ
