type t =
  { hashAlg: P11_mechanism_type.t
  ; mgf: P11_rsa_pkcs_mgf_type.t
  ; sLen: P11_ulong.t
  }
[@@deriving yojson]

let compare a b =
  let c = P11_mechanism_type.compare a.hashAlg b.hashAlg in
  if c <> 0 then
    c
  else
    let c = Unsigned.ULong.compare a.mgf b.mgf in
    if c <> 0 then
      c
    else
      Unsigned.ULong.compare a.sLen b.sLen
