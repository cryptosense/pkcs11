(** Parameters for [CKM_ECDH1_DERIVE] and [CKM_ECDH1_COFACTOR_DERIVE] ([CK_ECDH1_DERIVE_PARAMS]) *)
type _t

type t = _t Ctypes.structure

val make : P11_ecdh1_derive_params.t -> t

val view : t -> P11_ecdh1_derive_params.t

val t : t Ctypes.typ
