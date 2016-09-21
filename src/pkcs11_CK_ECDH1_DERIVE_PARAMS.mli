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
