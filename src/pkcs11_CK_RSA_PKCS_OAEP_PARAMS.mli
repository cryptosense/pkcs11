(** Parameters for [CKM_RSA_PKCS_OAEP] ([CK_RSA_PKCS_OAEP_PARAMS]) *)
type _t
type t = _t Ctypes.structure

type u =
  {
    hashAlg: P11_mechanism_type.t;
    mgf: Pkcs11_CK_RSA_PKCS_MGF_TYPE.t;
    src: string option;
  }

val make: u -> t
val view: t -> u

val t : t Ctypes.typ

val compare : u -> u -> int
