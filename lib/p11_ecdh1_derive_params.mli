type t =
  { kdf : P11_ec_kdf.t
  ; shared_data : string option
  ; public_data : P11_hex_data.t }
[@@deriving eq, ord, show, yojson]
