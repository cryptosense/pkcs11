type t =
  { kdf: Pkcs11_CK_EC_KDF_TYPE.u
  ; shared_data: string option
  ; public_data: string
  ; private_data_len: P11_ulong.t
  ; private_data: P11_object_handle.t
  ; public_data2: string
  ; public_key: P11_object_handle.t
  }
[@@deriving ord,to_yojson]
