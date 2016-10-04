(** Parameters for [CKM_ECDH1_DERIVE] and [CKM_ECDH1_COFACTOR_DERIVE] ([CK_ECDH1_DERIVE_PARAMS]) *)
type _t
type t = _t Ctypes.structure

type u =
  { kdf: Pkcs11_CK_EC_KDF_TYPE.u
  ; shared_data: string option
  ; public_data: string
  } [@@deriving yojson]

val make : u -> t
val view : t -> u

val t : t Ctypes.typ

val compare : u -> u -> int
