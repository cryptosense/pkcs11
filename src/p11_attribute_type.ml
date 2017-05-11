type not_implemented = Pkcs11.CK_ATTRIBUTE_TYPE.not_implemented = NOT_IMPLEMENTED of string

type 'a t = 'a Pkcs11.CK_ATTRIBUTE_TYPE.u =
  | CKA_CLASS : P11_object_class.t t
  | CKA_TOKEN : bool t
  | CKA_PRIVATE : bool t
  | CKA_LABEL : string t
  | CKA_VALUE : string t
  | CKA_TRUSTED : bool t
  | CKA_CHECK_VALUE : not_implemented t
  | CKA_KEY_TYPE : P11_key_type.t t
  | CKA_SUBJECT : string t
  | CKA_ID : string t
  | CKA_SENSITIVE : bool t
  | CKA_ENCRYPT : bool t
  | CKA_DECRYPT : bool t
  | CKA_WRAP : bool t
  | CKA_UNWRAP : bool t
  | CKA_SIGN : bool t
  | CKA_SIGN_RECOVER : bool t
  | CKA_VERIFY : bool t
  | CKA_VERIFY_RECOVER : bool t
  | CKA_DERIVE : bool t
  | CKA_START_DATE : not_implemented t
  | CKA_END_DATE : not_implemented t
  | CKA_MODULUS : Pkcs11.CK_BIGINT.t t
  | CKA_MODULUS_BITS : Pkcs11.CK_ULONG.t t
  | CKA_PUBLIC_EXPONENT : Pkcs11.CK_BIGINT.t t
  | CKA_PRIVATE_EXPONENT : Pkcs11.CK_BIGINT.t t
  | CKA_PRIME_1 : Pkcs11.CK_BIGINT.t t
  | CKA_PRIME_2 : Pkcs11.CK_BIGINT.t t
  | CKA_EXPONENT_1 : Pkcs11.CK_BIGINT.t t
  | CKA_EXPONENT_2 : Pkcs11.CK_BIGINT.t t
  | CKA_COEFFICIENT : Pkcs11.CK_BIGINT.t t
  | CKA_PRIME : Pkcs11.CK_BIGINT.t t
  | CKA_SUBPRIME : Pkcs11.CK_BIGINT.t t
  | CKA_PRIME_BITS : Pkcs11.CK_ULONG.t t
  | CKA_SUBPRIME_BITS : Pkcs11.CK_ULONG.t t
  | CKA_VALUE_LEN : Pkcs11.CK_ULONG.t t
  | CKA_EXTRACTABLE : bool t
  | CKA_LOCAL : bool t
  | CKA_NEVER_EXTRACTABLE : bool t
  | CKA_ALWAYS_SENSITIVE : bool t
  | CKA_KEY_GEN_MECHANISM : P11_key_gen_mechanism.t t
  | CKA_MODIFIABLE : bool t
  (* | CKA_ECDSA_PARAMS : string t *)
  | CKA_EC_PARAMS : Key_parsers.Asn1.EC.Params.t t
  | CKA_EC_POINT : Key_parsers.Asn1.EC.point t
  | CKA_ALWAYS_AUTHENTICATE : bool t
  | CKA_WRAP_WITH_TRUSTED : bool t
  | CKA_WRAP_TEMPLATE : not_implemented t
  | CKA_UNWRAP_TEMPLATE : not_implemented t
  | CKA_ALLOWED_MECHANISMS : not_implemented t
  | CKA_CS_UNKNOWN: Unsigned.ULong.t -> not_implemented t

type pack = Pkcs11.CK_ATTRIBUTE_TYPE.pack = Pack : 'a t -> pack

let compare = Pkcs11.CK_ATTRIBUTE_TYPE.compare
let compare_pack = Pkcs11.CK_ATTRIBUTE_TYPE.compare_pack
let to_string = Pkcs11.CK_ATTRIBUTE_TYPE.to_string
let of_string = Pkcs11.CK_ATTRIBUTE_TYPE.of_string
let equal = Pkcs11.CK_ATTRIBUTE_TYPE.equal
let equal_pack = Pkcs11.CK_ATTRIBUTE_TYPE.equal_pack

let to_json attribute =
  try
    `String (to_string attribute)
  with Invalid_argument _ ->
    `Null

let pack_to_json (Pack attribute) = to_json attribute

let pack_to_yojson = pack_to_json

let pack_of_yojson = Ctypes_helpers.of_json_string ~typename:"attribute type" of_string

let elements =
  [
    Pack CKA_CLASS;
    Pack CKA_TOKEN;
    Pack CKA_PRIVATE;
    Pack CKA_LABEL;
    Pack CKA_VALUE;
    Pack CKA_TRUSTED;
    Pack CKA_KEY_TYPE;
    Pack CKA_SUBJECT;
    Pack CKA_ID;
    Pack CKA_SENSITIVE;
    Pack CKA_ENCRYPT;
    Pack CKA_DECRYPT;
    Pack CKA_WRAP;
    Pack CKA_UNWRAP;
    Pack CKA_SIGN;
    Pack CKA_SIGN_RECOVER;
    Pack CKA_VERIFY;
    Pack CKA_VERIFY_RECOVER;
    Pack CKA_DERIVE;
    Pack CKA_MODULUS;
    Pack CKA_MODULUS_BITS;
    Pack CKA_PUBLIC_EXPONENT;
    Pack CKA_PRIVATE_EXPONENT;
    Pack CKA_PRIME_1;
    Pack CKA_PRIME_2;
    Pack CKA_EXPONENT_1;
    Pack CKA_EXPONENT_2;
    Pack CKA_COEFFICIENT;
    Pack CKA_PRIME;
    Pack CKA_SUBPRIME;
    Pack CKA_PRIME_BITS;
    Pack CKA_SUBPRIME_BITS;
    Pack CKA_VALUE_LEN;
    Pack CKA_EXTRACTABLE;
    Pack CKA_LOCAL;
    Pack CKA_NEVER_EXTRACTABLE;
    Pack CKA_ALWAYS_SENSITIVE;
    Pack CKA_KEY_GEN_MECHANISM;
    Pack CKA_MODIFIABLE;
    Pack CKA_EC_PARAMS;
    Pack CKA_EC_POINT;
    Pack CKA_ALWAYS_AUTHENTICATE;
    Pack CKA_WRAP_WITH_TRUSTED;
  ]

let known_attribute_types = List.map (fun (Pack c) -> to_string c) elements
