type t =
  | CKK_RSA
  | CKK_DSA
  | CKK_DH
  | CKK_EC
  | CKK_X9_42_DH
  | CKK_KEA
  | CKK_GENERIC_SECRET
  | CKK_RC2
  | CKK_RC4
  | CKK_DES
  | CKK_DES2
  | CKK_DES3
  | CKK_CAST
  | CKK_CAST3
  | CKK_CAST128
  | CKK_RC5
  | CKK_IDEA
  | CKK_SKIPJACK
  | CKK_BATON
  | CKK_JUNIPER
  | CKK_CDMF
  | CKK_AES
  | CKK_BLOWFISH
  | CKK_TWOFISH
  | CKK_SECURID
  | CKK_HOTP
  | CKK_ACTI
  | CKK_CAMELLIA
  | CKK_ARIA
  | CKK_VENDOR_DEFINED
  | CKK_CS_UNKNOWN of P11_ulong.t
[@@deriving eq, ord, show]

let to_string = function
  | CKK_RSA -> "CKK_RSA"
  | CKK_DSA -> "CKK_DSA"
  | CKK_DH -> "CKK_DH"
  | CKK_EC -> "CKK_EC"
  | CKK_X9_42_DH -> "CKK_X9_42_DH"
  | CKK_KEA -> "CKK_KEA"
  | CKK_GENERIC_SECRET -> "CKK_GENERIC_SECRET"
  | CKK_RC2 -> "CKK_RC2"
  | CKK_RC4 -> "CKK_RC4"
  | CKK_DES -> "CKK_DES"
  | CKK_DES2 -> "CKK_DES2"
  | CKK_DES3 -> "CKK_DES3"
  | CKK_CAST -> "CKK_CAST"
  | CKK_CAST3 -> "CKK_CAST3"
  | CKK_CAST128 -> "CKK_CAST128"
  | CKK_RC5 -> "CKK_RC5"
  | CKK_IDEA -> "CKK_IDEA"
  | CKK_SKIPJACK -> "CKK_SKIPJACK"
  | CKK_BATON -> "CKK_BATON"
  | CKK_JUNIPER -> "CKK_JUNIPER"
  | CKK_CDMF -> "CKK_CDMF"
  | CKK_AES -> "CKK_AES"
  | CKK_BLOWFISH -> "CKK_BLOWFISH"
  | CKK_TWOFISH -> "CKK_TWOFISH"
  | CKK_SECURID -> "CKK_SECURID"
  | CKK_HOTP -> "CKK_HOTP"
  | CKK_ACTI -> "CKK_ACTI"
  | CKK_CAMELLIA -> "CKK_CAMELLIA"
  | CKK_ARIA -> "CKK_ARIA"
  | CKK_VENDOR_DEFINED -> "CKK_VENDOR_DEFINED"
  | CKK_CS_UNKNOWN x -> Unsigned.ULong.to_string x

let of_string = function
  | "CKK_RSA" -> CKK_RSA
  | "CKK_DSA" -> CKK_DSA
  | "CKK_DH" -> CKK_DH
  | "CKK_EC" -> CKK_EC
  | "CKK_ECDSA" -> CKK_EC
  | "CKK_X9_42_DH" -> CKK_X9_42_DH
  | "CKK_KEA" -> CKK_KEA
  | "CKK_GENERIC_SECRET" -> CKK_GENERIC_SECRET
  | "CKK_RC2" -> CKK_RC2
  | "CKK_RC4" -> CKK_RC4
  | "CKK_DES" -> CKK_DES
  | "CKK_DES2" -> CKK_DES2
  | "CKK_DES3" -> CKK_DES3
  | "CKK_CAST" -> CKK_CAST
  | "CKK_CAST3" -> CKK_CAST3
  | "CKK_CAST128" -> CKK_CAST128
  | "CKK_CAST5" -> CKK_CAST128
  | "CKK_RC5" -> CKK_RC5
  | "CKK_IDEA" -> CKK_IDEA
  | "CKK_SKIPJACK" -> CKK_SKIPJACK
  | "CKK_BATON" -> CKK_BATON
  | "CKK_JUNIPER" -> CKK_JUNIPER
  | "CKK_CDMF" -> CKK_CDMF
  | "CKK_AES" -> CKK_AES
  | "CKK_BLOWFISH" -> CKK_BLOWFISH
  | "CKK_TWOFISH" -> CKK_TWOFISH
  | "CKK_SECURID" -> CKK_SECURID
  | "CKK_HOTP" -> CKK_HOTP
  | "CKK_ACTI" -> CKK_ACTI
  | "CKK_CAMELLIA" -> CKK_CAMELLIA
  | "CKK_ARIA" -> CKK_ARIA
  | "CKK_VENDOR_DEFINED" -> CKK_VENDOR_DEFINED
  | x -> (
    try CKK_CS_UNKNOWN (Unsigned.ULong.of_string x) with
    | Sys.Break as e -> raise e
    | _ -> invalid_arg ("Pkcs11_CK_KEY_TYPE.of_string" ^ ": cannot find " ^ x))

let to_yojson key_type = `String (to_string key_type)

let of_yojson = P11_helpers.of_json_string ~typename:"key type" of_string
