type t =
  { hashAlg: P11_mechanism_type.t
  ; mgf: P11_rsa_pkcs_mgf_type.t
  ; sLen: Pkcs11_CK_ULONG.t
  }
[@@deriving ord,yojson]
