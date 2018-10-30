(** Parameters for [CKM_RSA_PKCS_OAEP] ([CK_RSA_PKCS_OAEP_PARAMS]) *)
type _t

type t = _t Ctypes.structure

val make : P11_rsa_pkcs_oaep_params.t -> t

val view : t -> P11_rsa_pkcs_oaep_params.t

val t : t Ctypes.typ
