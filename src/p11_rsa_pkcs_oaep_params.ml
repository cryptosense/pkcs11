type t =
  { hashAlg: P11_mechanism_type.t
  ; mgf: P11_rsa_pkcs_mgf_type.t
  ; src: Pkcs11_hex_data.t option
  }
[@@deriving ord,yojson]
