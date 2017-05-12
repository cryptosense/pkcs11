type t =
  { mechanism: P11_mechanism_type.t
  ; data: Pkcs11_hex_data.t
  }
[@@deriving yojson]

let compare a b =
  if P11_mechanism_type.equal a.mechanism b.mechanism then
    Pkcs11_hex_data.compare a.data b.data
  else
    P11_mechanism_type.compare a.mechanism b.mechanism
