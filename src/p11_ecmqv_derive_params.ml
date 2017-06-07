type t =
  { kdf: Pkcs11_CK_EC_KDF_TYPE.u
  ; shared_data: string option
  ; public_data: string
  ; private_data_len: P11_ulong.t
  ; private_data: Pkcs11_CK_OBJECT_HANDLE.t
  ; public_data2: string
  ; public_key: Pkcs11_CK_OBJECT_HANDLE.t
  }

let compare : t -> t -> int =
  Pervasives.compare

let to_yojson params =
  `Assoc
    [ "kdf", Pkcs11_CK_EC_KDF_TYPE.u_to_yojson params.kdf
    ; "shared_data", [%to_yojson: string option] params.shared_data
    ; "public_data", `String params.public_data
    ; "private_data_len", `String (Unsigned.ULong.to_string params.private_data_len)
    ; "private_data", `String (Unsigned.ULong.to_string params.private_data)
    ; "public_data2", `String params.public_data2
    ; "public_key", `String (Unsigned.ULong.to_string params.public_key)
    ]
