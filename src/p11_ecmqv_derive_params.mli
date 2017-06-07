type t =
  { kdf: Pkcs11_CK_EC_KDF_TYPE.u
  ; shared_data: string option
  ; public_data: string
  ; private_data_len: P11_ulong.t
  ; private_data: Pkcs11_CK_OBJECT_HANDLE.t
  ; public_data2: string
  ; public_key: Pkcs11_CK_OBJECT_HANDLE.t
  }
[@@deriving ord,to_yojson]
