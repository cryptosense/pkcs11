type t =
  { hashAlg : P11_mechanism_type.t
  ; mgf : P11_rsa_pkcs_mgf_type.t
  ; sLen : P11_ulong.t }
[@@deriving eq, ord, show, yojson]
