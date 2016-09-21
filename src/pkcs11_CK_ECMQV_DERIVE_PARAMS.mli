type _t
type t = _t Ctypes.structure

type u =
  { kdf: Pkcs11_CK_EC_KDF_TYPE.u
  ; shared_data: string option
  ; public_data: string
  ; private_data_len: Pkcs11_CK_ULONG.t
  ; private_data: Pkcs11_CK_OBJECT_HANDLE.t
  ; public_data2: string
  ; public_key: Pkcs11_CK_OBJECT_HANDLE.t
  }

val u_to_yojson: u -> Yojson.Safe.json

val make : u -> t
val view : t -> u

val t : t Ctypes.typ

val compare : u -> u -> int
