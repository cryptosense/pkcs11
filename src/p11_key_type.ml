type t = Pkcs11.CK_KEY_TYPE.u =
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
  | CKK_CS_UNKNOWN of Unsigned.ULong.t

let equal = Pkcs11.CK_KEY_TYPE.equal
let compare = Pkcs11.CK_KEY_TYPE.compare
let to_string = Pkcs11.CK_KEY_TYPE.to_string
let of_string = Pkcs11.CK_KEY_TYPE.of_string

let to_yojson key_type =
  `String (to_string key_type)

let of_yojson = Ctypes_helpers.of_json_string ~typename:"key type" of_string
