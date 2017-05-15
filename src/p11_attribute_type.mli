type not_implemented = Pkcs11.CK_ATTRIBUTE_TYPE.not_implemented = NOT_IMPLEMENTED of string

type 'a t = 'a Pkcs11.CK_ATTRIBUTE_TYPE.u =
  | CKA_CLASS : Pkcs11.CK_OBJECT_CLASS.u t
  | CKA_TOKEN : bool t
  | CKA_PRIVATE : bool t
  | CKA_LABEL : string t
  | CKA_VALUE : string t
  | CKA_TRUSTED : bool t
  | CKA_CHECK_VALUE : not_implemented t
  | CKA_KEY_TYPE : Pkcs11.CK_KEY_TYPE.u t
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
  [@@deriving yojson]

val of_string : string -> pack


val compare: 'a t -> 'b t -> int
val compare_pack: pack -> pack -> int
val equal : 'a t -> 'b t -> bool
val equal_pack: pack -> pack -> bool

val to_string : 'a t -> string

val pack_to_json : pack -> Yojson.Safe.json

val elements: pack list
val known_attribute_types : string list
