(** Parameter for [CKM_AES_GCM]. ([CK_GCM_PARAMS]) *)

type s

type t = s Ctypes.structure

val t : t Ctypes.typ

val pIv : (Pkcs11_CK_BYTE.t Ctypes_helpers.Reachable_ptr.t, t) Ctypes.field

val ulIvLen : (P11_ulong.t, t) Ctypes.field

val pAAD : (Pkcs11_CK_BYTE.t Ctypes_helpers.Reachable_ptr.t, t) Ctypes.field

val ulAADLen : (P11_ulong.t, t) Ctypes.field

val ulTagBits : (P11_ulong.t, t) Ctypes.field

val make : P11_gcm_params.t -> t

val view : t -> P11_gcm_params.t
