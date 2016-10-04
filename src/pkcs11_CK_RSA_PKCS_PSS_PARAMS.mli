(** Parameters for [CKM_RSA_PKCS_PSS] ([CK_RSA_PKCS_PSS_PARAMS]) *)
type _t
type t = _t Ctypes.structure

type u =
  {
    hashAlg: Pkcs11_CK_MECHANISM_TYPE.u;
    mgf: Pkcs11_CK_RSA_PKCS_MGF_TYPE.t;
    sLen: Pkcs11_CK_ULONG.t;
  }

val make: u -> t
val view: t -> u

val compare : u -> u -> int

val t : t Ctypes.typ
