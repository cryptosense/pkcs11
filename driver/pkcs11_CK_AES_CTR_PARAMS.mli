(** Parameter for [CKM_AES_CTR]. ([CK_AES_CTR_PARAMS]) *)

type s

type t = s Ctypes.structure

val t : t Ctypes.typ

val bits : (Unsigned.ULong.t, t) Ctypes.field

val block : (char Ctypes.carray, t) Ctypes.field

val make : P11_aes_ctr_params.t -> t

val view : t -> P11_aes_ctr_params.t
