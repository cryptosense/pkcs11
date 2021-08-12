type t = P11_ulong.t

let view_error n = Pkcs11_log.log @@ Printf.sprintf "Unknown CKK code: 0x%Lx" n

let with_value x = Unsigned.ULong.of_string @@ Int64.to_string x

let _CKK_RSA = with_value 0x00000000L

let _CKK_DSA = with_value 0x00000001L

let _CKK_DH = with_value 0x00000002L

let _CKK_EC = with_value 0x00000003L

let _CKK_X9_42_DH = with_value 0x00000004L

let _CKK_KEA = with_value 0x00000005L

let _CKK_GENERIC_SECRET = with_value 0x00000010L

let _CKK_RC2 = with_value 0x00000011L

let _CKK_RC4 = with_value 0x00000012L

let _CKK_DES = with_value 0x00000013L

let _CKK_DES2 = with_value 0x00000014L

let _CKK_DES3 = with_value 0x00000015L

let _CKK_CAST = with_value 0x00000016L

let _CKK_CAST3 = with_value 0x00000017L

let _CKK_CAST128 = with_value 0x00000018L

let _CKK_RC5 = with_value 0x00000019L

let _CKK_IDEA = with_value 0x0000001AL

let _CKK_SKIPJACK = with_value 0x0000001BL

let _CKK_BATON = with_value 0x0000001CL

let _CKK_JUNIPER = with_value 0x0000001DL

let _CKK_CDMF = with_value 0x0000001EL

let _CKK_AES = with_value 0x0000001FL

let _CKK_BLOWFISH = with_value 0x00000020L

let _CKK_TWOFISH = with_value 0x00000021L

let _CKK_SECURID = with_value 0x00000022L

let _CKK_HOTP = with_value 0x00000023L

let _CKK_ACTI = with_value 0x00000024L

let _CKK_CAMELLIA = with_value 0x00000025L

let _CKK_ARIA = with_value 0x00000026L

let _CKK_VENDOR_DEFINED = with_value 0x80000000L

let make =
  let open P11_key_type in
  function
  | CKK_RSA -> _CKK_RSA
  | CKK_DSA -> _CKK_DSA
  | CKK_DH -> _CKK_DH
  | CKK_EC -> _CKK_EC
  | CKK_X9_42_DH -> _CKK_X9_42_DH
  | CKK_KEA -> _CKK_KEA
  | CKK_GENERIC_SECRET -> _CKK_GENERIC_SECRET
  | CKK_RC2 -> _CKK_RC2
  | CKK_RC4 -> _CKK_RC4
  | CKK_DES -> _CKK_DES
  | CKK_DES2 -> _CKK_DES2
  | CKK_DES3 -> _CKK_DES3
  | CKK_CAST -> _CKK_CAST
  | CKK_CAST3 -> _CKK_CAST3
  | CKK_CAST128 -> _CKK_CAST128
  | CKK_RC5 -> _CKK_RC5
  | CKK_IDEA -> _CKK_IDEA
  | CKK_SKIPJACK -> _CKK_SKIPJACK
  | CKK_BATON -> _CKK_BATON
  | CKK_JUNIPER -> _CKK_JUNIPER
  | CKK_CDMF -> _CKK_CDMF
  | CKK_AES -> _CKK_AES
  | CKK_BLOWFISH -> _CKK_BLOWFISH
  | CKK_TWOFISH -> _CKK_TWOFISH
  | CKK_SECURID -> _CKK_SECURID
  | CKK_HOTP -> _CKK_HOTP
  | CKK_ACTI -> _CKK_ACTI
  | CKK_CAMELLIA -> _CKK_CAMELLIA
  | CKK_ARIA -> _CKK_ARIA
  | CKK_VENDOR_DEFINED -> _CKK_VENDOR_DEFINED
  | CKK_CS_UNKNOWN x -> x

let view t =
  let open P11_key_type in
  let is value = Unsigned.ULong.compare t value = 0 in
  match () with
  | _ when is _CKK_RSA -> CKK_RSA
  | _ when is _CKK_DSA -> CKK_DSA
  | _ when is _CKK_DH -> CKK_DH
  | _ when is _CKK_EC -> CKK_EC
  | _ when is _CKK_X9_42_DH -> CKK_X9_42_DH
  | _ when is _CKK_KEA -> CKK_KEA
  | _ when is _CKK_GENERIC_SECRET -> CKK_GENERIC_SECRET
  | _ when is _CKK_RC2 -> CKK_RC2
  | _ when is _CKK_RC4 -> CKK_RC4
  | _ when is _CKK_DES -> CKK_DES
  | _ when is _CKK_DES2 -> CKK_DES2
  | _ when is _CKK_DES3 -> CKK_DES3
  | _ when is _CKK_CAST -> CKK_CAST
  | _ when is _CKK_CAST3 -> CKK_CAST3
  | _ when is _CKK_CAST128 -> CKK_CAST128
  | _ when is _CKK_RC5 -> CKK_RC5
  | _ when is _CKK_IDEA -> CKK_IDEA
  | _ when is _CKK_SKIPJACK -> CKK_SKIPJACK
  | _ when is _CKK_BATON -> CKK_BATON
  | _ when is _CKK_JUNIPER -> CKK_JUNIPER
  | _ when is _CKK_CDMF -> CKK_CDMF
  | _ when is _CKK_AES -> CKK_AES
  | _ when is _CKK_BLOWFISH -> CKK_BLOWFISH
  | _ when is _CKK_TWOFISH -> CKK_TWOFISH
  | _ when is _CKK_SECURID -> CKK_SECURID
  | _ when is _CKK_HOTP -> CKK_HOTP
  | _ when is _CKK_ACTI -> CKK_ACTI
  | _ when is _CKK_CAMELLIA -> CKK_CAMELLIA
  | _ when is _CKK_ARIA -> CKK_ARIA
  | _ when is _CKK_VENDOR_DEFINED -> CKK_VENDOR_DEFINED
  | _ ->
    view_error (Int64.of_string (Unsigned.ULong.to_string t));
    CKK_CS_UNKNOWN t
