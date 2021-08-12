(** Information about a slot ([CK_SLOT_INFO]) *)
type _t

type t = _t Ctypes.structure

val make : P11_slot_info.t -> t

val view : t -> P11_slot_info.t

val ck_slot_info : t Ctypes.typ
