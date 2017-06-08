type t =
  { kdf: P11_ec_kdf.t
  ; shared_data: string option
  ; public_data: string
  ; private_data_len: P11_ulong.t
  ; private_data: P11_object_handle.t
  ; public_data2: string
  ; public_key: P11_object_handle.t
  }

let compare : t -> t -> int =
  Pervasives.compare

let to_yojson params =
  `Assoc
    [ "kdf", P11_ec_kdf.to_yojson params.kdf
    ; "shared_data", [%to_yojson: string option] params.shared_data
    ; "public_data", `String params.public_data
    ; "private_data_len", `String (Unsigned.ULong.to_string params.private_data_len)
    ; "private_data", `String (Unsigned.ULong.to_string params.private_data)
    ; "public_data2", `String params.public_data2
    ; "public_key", `String (Unsigned.ULong.to_string params.public_key)
    ]
