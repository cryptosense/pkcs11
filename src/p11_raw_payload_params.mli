type t =
  { mechanism: P11_mechanism_type.t
  ; data: P11_hex_data.t
  }
[@@deriving ord,yojson]
