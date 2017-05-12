type t =
  { mechanism: P11_mechanism_type.t
  ; data: Pkcs11_hex_data.t
  }
[@@deriving ord,yojson]
