(** Parameters for [CKM_ECMQV_DERIVE] ([CK_ECMQV_DERIVE_PARAMS]) *)
type _t

type t = _t Ctypes.structure

val make : P11_ecmqv_derive_params.t -> t

val view : t -> P11_ecmqv_derive_params.t

val t : t Ctypes.typ
