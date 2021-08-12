type t =
  { kdf : P11_ec_kdf.t
  ; shared_data : string option
  ; public_data : string
  ; private_data_len : P11_ulong.t
  ; private_data : P11_object_handle.t
  ; public_data2 : string
  ; public_key : P11_object_handle.t }
[@@deriving eq, ord, show, to_yojson]
