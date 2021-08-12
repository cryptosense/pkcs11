(** Mechanisms (type and value) ([CK_KEY_TYPE]) *)
type _t

type t = _t Ctypes.structure

val mechanism : (Pkcs11_CK_MECHANISM_TYPE.t, t) Ctypes.field

val parameter : (unit Ctypes_helpers.Reachable_ptr.t, t) Ctypes.field

val parameter_len : (P11_ulong.t, t) Ctypes.field

val make : P11_mechanism.t -> t

val view : t -> P11_mechanism.t

val ck_mechanism : t Ctypes.typ
