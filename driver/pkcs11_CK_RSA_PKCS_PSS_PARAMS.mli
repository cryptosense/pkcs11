(** Parameters for [CKM_RSA_PKCS_PSS] ([CK_RSA_PKCS_PSS_PARAMS]) *)
type _t

type t = _t Ctypes.structure

val make : P11_rsa_pkcs_pss_params.t -> t

val view : t -> P11_rsa_pkcs_pss_params.t

val t : t Ctypes.typ
