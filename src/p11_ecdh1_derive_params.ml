type t =
  { kdf: Pkcs11_CK_EC_KDF_TYPE.u
  ; shared_data: string option
  ; public_data: P11_hex_data.t
  }
[@@deriving yojson]

let compare : t -> t -> int =
  Pervasives.compare
