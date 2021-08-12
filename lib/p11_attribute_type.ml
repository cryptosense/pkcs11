type not_implemented = NOT_IMPLEMENTED of string

type 'a t =
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
  | CKA_MODULUS : P11_bigint.t t
  | CKA_MODULUS_BITS : P11_ulong.t t
  | CKA_PUBLIC_EXPONENT : P11_bigint.t t
  | CKA_PRIVATE_EXPONENT : P11_bigint.t t
  | CKA_PRIME_1 : P11_bigint.t t
  | CKA_PRIME_2 : P11_bigint.t t
  | CKA_EXPONENT_1 : P11_bigint.t t
  | CKA_EXPONENT_2 : P11_bigint.t t
  | CKA_COEFFICIENT : P11_bigint.t t
  | CKA_PRIME : P11_bigint.t t
  | CKA_SUBPRIME : P11_bigint.t t
  | CKA_BASE : P11_bigint.t t
  | CKA_PRIME_BITS : P11_ulong.t t
  | CKA_SUBPRIME_BITS : P11_ulong.t t
  | CKA_VALUE_LEN : P11_ulong.t t
  | CKA_EXTRACTABLE : bool t
  | CKA_LOCAL : bool t
  | CKA_NEVER_EXTRACTABLE : bool t
  | CKA_ALWAYS_SENSITIVE : bool t
  | CKA_KEY_GEN_MECHANISM : P11_key_gen_mechanism.t t
  | CKA_MODIFIABLE : bool t
  | CKA_EC_PARAMS : string t
  | CKA_EC_POINT : string t
  | CKA_ALWAYS_AUTHENTICATE : bool t
  | CKA_WRAP_WITH_TRUSTED : bool t
  | CKA_WRAP_TEMPLATE : not_implemented t
  | CKA_UNWRAP_TEMPLATE : not_implemented t
  | CKA_ALLOWED_MECHANISMS : not_implemented t
  | CKA_CS_UNKNOWN : Unsigned.ULong.t -> not_implemented t

type pack = Pack : 'a t -> pack

let to_string : type a. a t -> string = function
  | CKA_CLASS -> "CKA_CLASS"
  | CKA_TOKEN -> "CKA_TOKEN"
  | CKA_PRIVATE -> "CKA_PRIVATE"
  | CKA_LABEL -> "CKA_LABEL"
  | CKA_VALUE -> "CKA_VALUE"
  | CKA_TRUSTED -> "CKA_TRUSTED"
  | CKA_CHECK_VALUE -> "CKA_CHECK_VALUE"
  | CKA_KEY_TYPE -> "CKA_KEY_TYPE"
  | CKA_SUBJECT -> "CKA_SUBJECT"
  | CKA_ID -> "CKA_ID"
  | CKA_SENSITIVE -> "CKA_SENSITIVE"
  | CKA_ENCRYPT -> "CKA_ENCRYPT"
  | CKA_DECRYPT -> "CKA_DECRYPT"
  | CKA_WRAP -> "CKA_WRAP"
  | CKA_UNWRAP -> "CKA_UNWRAP"
  | CKA_SIGN -> "CKA_SIGN"
  | CKA_SIGN_RECOVER -> "CKA_SIGN_RECOVER"
  | CKA_VERIFY -> "CKA_VERIFY"
  | CKA_VERIFY_RECOVER -> "CKA_VERIFY_RECOVER"
  | CKA_DERIVE -> "CKA_DERIVE"
  | CKA_START_DATE -> "CKA_START_DATE"
  | CKA_END_DATE -> "CKA_END_DATE"
  | CKA_MODULUS -> "CKA_MODULUS"
  | CKA_MODULUS_BITS -> "CKA_MODULUS_BITS"
  | CKA_PUBLIC_EXPONENT -> "CKA_PUBLIC_EXPONENT"
  | CKA_PRIVATE_EXPONENT -> "CKA_PRIVATE_EXPONENT"
  | CKA_PRIME_1 -> "CKA_PRIME_1"
  | CKA_PRIME_2 -> "CKA_PRIME_2"
  | CKA_EXPONENT_1 -> "CKA_EXPONENT_1"
  | CKA_EXPONENT_2 -> "CKA_EXPONENT_2"
  | CKA_COEFFICIENT -> "CKA_COEFFICIENT"
  | CKA_PRIME -> "CKA_PRIME"
  | CKA_SUBPRIME -> "CKA_SUBPRIME"
  | CKA_BASE -> "CKA_BASE"
  | CKA_PRIME_BITS -> "CKA_PRIME_BITS"
  | CKA_SUBPRIME_BITS -> "CKA_SUBPRIME_BITS"
  | CKA_VALUE_LEN -> "CKA_VALUE_LEN"
  | CKA_EXTRACTABLE -> "CKA_EXTRACTABLE"
  | CKA_LOCAL -> "CKA_LOCAL"
  | CKA_NEVER_EXTRACTABLE -> "CKA_NEVER_EXTRACTABLE"
  | CKA_ALWAYS_SENSITIVE -> "CKA_ALWAYS_SENSITIVE"
  | CKA_KEY_GEN_MECHANISM -> "CKA_KEY_GEN_MECHANISM"
  | CKA_MODIFIABLE -> "CKA_MODIFIABLE"
  (* | CKA_ECDSA_PARAMS -> "CKA_ECDSA_PARAMS" *)
  | CKA_EC_PARAMS -> "CKA_EC_PARAMS"
  | CKA_EC_POINT -> "CKA_EC_POINT"
  | CKA_ALWAYS_AUTHENTICATE -> "CKA_ALWAYS_AUTHENTICATE"
  | CKA_WRAP_WITH_TRUSTED -> "CKA_WRAP_WITH_TRUSTED"
  | CKA_WRAP_TEMPLATE -> "CKA_WRAP_TEMPLATE"
  | CKA_UNWRAP_TEMPLATE -> "CKA_UNWRAP_TEMPLATE"
  | CKA_ALLOWED_MECHANISMS -> "CKA_ALLOWED_MECHANISMS"
  | CKA_CS_UNKNOWN ul -> Unsigned.ULong.to_string ul

let of_string = function
  | "CKA_CLASS" -> Pack CKA_CLASS
  | "CKA_TOKEN" -> Pack CKA_TOKEN
  | "CKA_PRIVATE" -> Pack CKA_PRIVATE
  | "CKA_LABEL" -> Pack CKA_LABEL
  | "CKA_VALUE" -> Pack CKA_VALUE
  | "CKA_TRUSTED" -> Pack CKA_TRUSTED
  | "CKA_CHECK_VALUE" -> Pack CKA_CHECK_VALUE
  | "CKA_KEY_TYPE" -> Pack CKA_KEY_TYPE
  | "CKA_SUBJECT" -> Pack CKA_SUBJECT
  | "CKA_ID" -> Pack CKA_ID
  | "CKA_SENSITIVE" -> Pack CKA_SENSITIVE
  | "CKA_ENCRYPT" -> Pack CKA_ENCRYPT
  | "CKA_DECRYPT" -> Pack CKA_DECRYPT
  | "CKA_WRAP" -> Pack CKA_WRAP
  | "CKA_UNWRAP" -> Pack CKA_UNWRAP
  | "CKA_SIGN" -> Pack CKA_SIGN
  | "CKA_SIGN_RECOVER" -> Pack CKA_SIGN_RECOVER
  | "CKA_VERIFY" -> Pack CKA_VERIFY
  | "CKA_VERIFY_RECOVER" -> Pack CKA_VERIFY_RECOVER
  | "CKA_DERIVE" -> Pack CKA_DERIVE
  | "CKA_START_DATE" -> Pack CKA_START_DATE
  | "CKA_END_DATE" -> Pack CKA_END_DATE
  | "CKA_MODULUS" -> Pack CKA_MODULUS
  | "CKA_MODULUS_BITS" -> Pack CKA_MODULUS_BITS
  | "CKA_PUBLIC_EXPONENT" -> Pack CKA_PUBLIC_EXPONENT
  | "CKA_PRIVATE_EXPONENT" -> Pack CKA_PRIVATE_EXPONENT
  | "CKA_PRIME_1" -> Pack CKA_PRIME_1
  | "CKA_PRIME_2" -> Pack CKA_PRIME_2
  | "CKA_EXPONENT_1" -> Pack CKA_EXPONENT_1
  | "CKA_EXPONENT_2" -> Pack CKA_EXPONENT_2
  | "CKA_COEFFICIENT" -> Pack CKA_COEFFICIENT
  | "CKA_PRIME" -> Pack CKA_PRIME
  | "CKA_SUBPRIME" -> Pack CKA_SUBPRIME
  | "CKA_BASE" -> Pack CKA_BASE
  | "CKA_PRIME_BITS" -> Pack CKA_PRIME_BITS
  | "CKA_SUBPRIME_BITS" -> Pack CKA_SUBPRIME_BITS
  | "CKA_SUB_PRIME_BITS" -> Pack CKA_SUBPRIME_BITS
  | "CKA_VALUE_LEN" -> Pack CKA_VALUE_LEN
  | "CKA_EXTRACTABLE" -> Pack CKA_EXTRACTABLE
  | "CKA_LOCAL" -> Pack CKA_LOCAL
  | "CKA_NEVER_EXTRACTABLE" -> Pack CKA_NEVER_EXTRACTABLE
  | "CKA_ALWAYS_SENSITIVE" -> Pack CKA_ALWAYS_SENSITIVE
  | "CKA_KEY_GEN_MECHANISM" -> Pack CKA_KEY_GEN_MECHANISM
  | "CKA_MODIFIABLE" -> Pack CKA_MODIFIABLE
  | "CKA_ECDSA_PARAMS" -> Pack CKA_EC_PARAMS
  | "CKA_EC_PARAMS" -> Pack CKA_EC_PARAMS
  | "CKA_EC_POINT" -> Pack CKA_EC_POINT
  | "CKA_ALWAYS_AUTHENTICATE" -> Pack CKA_ALWAYS_AUTHENTICATE
  | "CKA_WRAP_WITH_TRUSTED" -> Pack CKA_WRAP_WITH_TRUSTED
  | "CKA_WRAP_TEMPLATE" -> Pack CKA_WRAP_TEMPLATE
  | "CKA_UNWRAP_TEMPLATE" -> Pack CKA_UNWRAP_TEMPLATE
  | "CKA_ALLOWED_MECHANISMS" -> Pack CKA_ALLOWED_MECHANISMS
  | s -> (
    try Pack (CKA_CS_UNKNOWN (Unsigned.ULong.of_string s)) with
    | Failure _ -> invalid_arg "CK_ATTRIBUTE_TYPE.of_string")

module Encoding = struct
  let ( ! ) x = Unsigned.ULong.of_string (Int64.to_string x)

  let ckf_ARRAY_ATTRIBUTE = 0x40000000L

  let _CKA_CLASS = !0x00000000L

  let _CKA_TOKEN = !0x00000001L

  let _CKA_PRIVATE = !0x00000002L

  let _CKA_LABEL = !0x00000003L

  let _CKA_APPLICATION = !0x00000010L

  let _CKA_VALUE = !0x00000011L

  let _CKA_OBJECT_ID = !0x00000012L

  let _CKA_CERTIFICATE_TYPE = !0x00000080L

  let _CKA_ISSUER = !0x00000081L

  let _CKA_SERIAL_NUMBER = !0x00000082L

  let _CKA_AC_ISSUER = !0x00000083L

  let _CKA_OWNER = !0x00000084L

  let _CKA_ATTR_TYPES = !0x00000085L

  let _CKA_TRUSTED = !0x00000086L

  let _CKA_CERTIFICATE_CATEGORY = !0x00000087L

  let _CKA_JAVA_MIDP_SECURITY_DOMAIN = !0x00000088L

  let _CKA_URL = !0x00000089L

  let _CKA_HASH_OF_SUBJECT_PUBLIC_KEY = !0x0000008AL

  let _CKA_HASH_OF_ISSUER_PUBLIC_KEY = !0x0000008BL

  let _CKA_CHECK_VALUE = !0x00000090L

  let _CKA_KEY_TYPE = !0x00000100L

  let _CKA_SUBJECT = !0x00000101L

  let _CKA_ID = !0x00000102L

  let _CKA_SENSITIVE = !0x00000103L

  let _CKA_ENCRYPT = !0x00000104L

  let _CKA_DECRYPT = !0x00000105L

  let _CKA_WRAP = !0x00000106L

  let _CKA_UNWRAP = !0x00000107L

  let _CKA_SIGN = !0x00000108L

  let _CKA_SIGN_RECOVER = !0x00000109L

  let _CKA_VERIFY = !0x0000010AL

  let _CKA_VERIFY_RECOVER = !0x0000010BL

  let _CKA_DERIVE = !0x0000010CL

  let _CKA_START_DATE = !0x00000110L

  let _CKA_END_DATE = !0x00000111L

  let _CKA_MODULUS = !0x00000120L

  let _CKA_MODULUS_BITS = !0x00000121L

  let _CKA_PUBLIC_EXPONENT = !0x00000122L

  let _CKA_PRIVATE_EXPONENT = !0x00000123L

  let _CKA_PRIME_1 = !0x00000124L

  let _CKA_PRIME_2 = !0x00000125L

  let _CKA_EXPONENT_1 = !0x00000126L

  let _CKA_EXPONENT_2 = !0x00000127L

  let _CKA_COEFFICIENT = !0x00000128L

  let _CKA_PRIME = !0x00000130L

  let _CKA_SUBPRIME = !0x00000131L

  let _CKA_BASE = !0x00000132L

  let _CKA_PRIME_BITS = !0x00000133L

  let _CKA_SUBPRIME_BITS = !0x00000134L

  let _CKA_VALUE_BITS = !0x00000160L

  let _CKA_VALUE_LEN = !0x00000161L

  let _CKA_EXTRACTABLE = !0x00000162L

  let _CKA_LOCAL = !0x00000163L

  let _CKA_NEVER_EXTRACTABLE = !0x00000164L

  let _CKA_ALWAYS_SENSITIVE = !0x00000165L

  let _CKA_KEY_GEN_MECHANISM = !0x00000166L

  let _CKA_MODIFIABLE = !0x00000170L

  let _CKA_EC_PARAMS = !0x00000180L

  let _CKA_EC_POINT = !0x00000181L

  let _CKA_SECONDARY_AUTH = !0x00000200L

  let _CKA_AUTH_PIN_FLAGS = !0x00000201L

  let _CKA_ALWAYS_AUTHENTICATE = !0x00000202L

  let _CKA_WRAP_WITH_TRUSTED = !0x00000210L

  let _CKA_WRAP_TEMPLATE = !(Int64.logor ckf_ARRAY_ATTRIBUTE 0x00000211L)

  let _CKA_UNWRAP_TEMPLATE = !(Int64.logor ckf_ARRAY_ATTRIBUTE 0x00000212L)

  let _CKA_OTP_FORMAT = !0x00000220L

  let _CKA_OTP_LENGTH = !0x00000221L

  let _CKA_OTP_TIME_INTERVAL = !0x00000222L

  let _CKA_OTP_USER_FRIENDLY_MODE = !0x00000223L

  let _CKA_OTP_CHALLENGE_REQUIREMENT = !0x00000224L

  let _CKA_OTP_TIME_REQUIREMENT = !0x00000225L

  let _CKA_OTP_COUNTER_REQUIREMENT = !0x00000226L

  let _CKA_OTP_PIN_REQUIREMENT = !0x00000227L

  let _CKA_OTP_COUNTER = !0x0000022EL

  let _CKA_OTP_TIME = !0x0000022FL

  let _CKA_OTP_USER_IDENTIFIER = !0x0000022AL

  let _CKA_OTP_SERVICE_IDENTIFIER = !0x0000022BL

  let _CKA_OTP_SERVICE_LOGO = !0x0000022CL

  let _CKA_OTP_SERVICE_LOGO_TYPE = !0x0000022DL

  let _CKA_HW_FEATURE_TYPE = !0x00000300L

  let _CKA_RESET_ON_INIT = !0x00000301L

  let _CKA_HAS_RESET = !0x00000302L

  let _CKA_PIXEL_X = !0x00000400L

  let _CKA_PIXEL_Y = !0x00000401L

  let _CKA_RESOLUTION = !0x00000402L

  let _CKA_CHAR_ROWS = !0x00000403L

  let _CKA_CHAR_COLUMNS = !0x00000404L

  let _CKA_COLOR = !0x00000405L

  let _CKA_BITS_PER_PIXEL = !0x00000406L

  let _CKA_CHAR_SETS = !0x00000480L

  let _CKA_ENCODING_METHODS = !0x00000481L

  let _CKA_MIME_TYPES = !0x00000482L

  let _CKA_MECHANISM_TYPE = !0x00000500L

  let _CKA_REQUIRED_CMS_ATTRIBUTES = !0x00000501L

  let _CKA_DEFAULT_CMS_ATTRIBUTES = !0x00000502L

  let _CKA_SUPPORTED_CMS_ATTRIBUTES = !0x00000503L

  let _CKA_ALLOWED_MECHANISMS = !(Int64.logor ckf_ARRAY_ATTRIBUTE 0x00000600L)

  let _CKA_VENDOR_DEFINED = !0x80000000L

  let make (type s) (x : s t) : Unsigned.ULong.t =
    match x with
    | CKA_CLASS -> _CKA_CLASS
    | CKA_TOKEN -> _CKA_TOKEN
    | CKA_PRIVATE -> _CKA_PRIVATE
    | CKA_LABEL -> _CKA_LABEL
    | CKA_VALUE -> _CKA_VALUE
    | CKA_TRUSTED -> _CKA_TRUSTED
    | CKA_CHECK_VALUE -> _CKA_CHECK_VALUE
    | CKA_KEY_TYPE -> _CKA_KEY_TYPE
    | CKA_SUBJECT -> _CKA_SUBJECT
    | CKA_ID -> _CKA_ID
    | CKA_SENSITIVE -> _CKA_SENSITIVE
    | CKA_ENCRYPT -> _CKA_ENCRYPT
    | CKA_DECRYPT -> _CKA_DECRYPT
    | CKA_WRAP -> _CKA_WRAP
    | CKA_UNWRAP -> _CKA_UNWRAP
    | CKA_SIGN -> _CKA_SIGN
    | CKA_SIGN_RECOVER -> _CKA_SIGN_RECOVER
    | CKA_VERIFY -> _CKA_VERIFY
    | CKA_VERIFY_RECOVER -> _CKA_VERIFY_RECOVER
    | CKA_DERIVE -> _CKA_DERIVE
    | CKA_START_DATE -> _CKA_START_DATE
    | CKA_END_DATE -> _CKA_END_DATE
    | CKA_MODULUS -> _CKA_MODULUS
    | CKA_MODULUS_BITS -> _CKA_MODULUS_BITS
    | CKA_PUBLIC_EXPONENT -> _CKA_PUBLIC_EXPONENT
    | CKA_PRIVATE_EXPONENT -> _CKA_PRIVATE_EXPONENT
    | CKA_PRIME_1 -> _CKA_PRIME_1
    | CKA_PRIME_2 -> _CKA_PRIME_2
    | CKA_EXPONENT_1 -> _CKA_EXPONENT_1
    | CKA_EXPONENT_2 -> _CKA_EXPONENT_2
    | CKA_COEFFICIENT -> _CKA_COEFFICIENT
    | CKA_PRIME -> _CKA_PRIME
    | CKA_SUBPRIME -> _CKA_SUBPRIME
    | CKA_BASE -> _CKA_BASE
    | CKA_PRIME_BITS -> _CKA_PRIME_BITS
    | CKA_SUBPRIME_BITS -> _CKA_SUBPRIME_BITS
    | CKA_VALUE_LEN -> _CKA_VALUE_LEN
    | CKA_EXTRACTABLE -> _CKA_EXTRACTABLE
    | CKA_LOCAL -> _CKA_LOCAL
    | CKA_NEVER_EXTRACTABLE -> _CKA_NEVER_EXTRACTABLE
    | CKA_ALWAYS_SENSITIVE -> _CKA_ALWAYS_SENSITIVE
    | CKA_KEY_GEN_MECHANISM -> _CKA_KEY_GEN_MECHANISM
    | CKA_MODIFIABLE -> _CKA_MODIFIABLE
    | CKA_EC_PARAMS -> _CKA_EC_PARAMS
    | CKA_EC_POINT -> _CKA_EC_POINT
    | CKA_ALWAYS_AUTHENTICATE -> _CKA_ALWAYS_AUTHENTICATE
    | CKA_WRAP_WITH_TRUSTED -> _CKA_WRAP_WITH_TRUSTED
    | CKA_WRAP_TEMPLATE -> _CKA_WRAP_TEMPLATE
    | CKA_UNWRAP_TEMPLATE -> _CKA_UNWRAP_TEMPLATE
    | CKA_ALLOWED_MECHANISMS -> _CKA_ALLOWED_MECHANISMS
    | CKA_CS_UNKNOWN ul -> ul
end

type (_, _) comparison =
  | Equal : ('a, 'a) comparison
  | Not_equal : int -> ('a, 'b) comparison

let compare a b =
  let a = Encoding.make a in
  let b = Encoding.make b in
  Unsigned.ULong.compare a b

let compare' : type a b. a t -> b t -> (a, b) comparison =
 fun a b ->
  let a' = Encoding.make a in
  let b' = Encoding.make b in
  let n = P11_ulong.compare a' b' in
  if n <> 0 then
    Not_equal n
  else
    match (a, b) with
    | (CKA_CLASS, CKA_CLASS) -> Equal
    | (CKA_TOKEN, CKA_TOKEN) -> Equal
    | (CKA_PRIVATE, CKA_PRIVATE) -> Equal
    | (CKA_LABEL, CKA_LABEL) -> Equal
    | (CKA_VALUE, CKA_VALUE) -> Equal
    | (CKA_TRUSTED, CKA_TRUSTED) -> Equal
    | (CKA_CHECK_VALUE, CKA_CHECK_VALUE) -> Equal
    | (CKA_KEY_TYPE, CKA_KEY_TYPE) -> Equal
    | (CKA_SUBJECT, CKA_SUBJECT) -> Equal
    | (CKA_ID, CKA_ID) -> Equal
    | (CKA_SENSITIVE, CKA_SENSITIVE) -> Equal
    | (CKA_ENCRYPT, CKA_ENCRYPT) -> Equal
    | (CKA_DECRYPT, CKA_DECRYPT) -> Equal
    | (CKA_WRAP, CKA_WRAP) -> Equal
    | (CKA_UNWRAP, CKA_UNWRAP) -> Equal
    | (CKA_SIGN, CKA_SIGN) -> Equal
    | (CKA_SIGN_RECOVER, CKA_SIGN_RECOVER) -> Equal
    | (CKA_VERIFY, CKA_VERIFY) -> Equal
    | (CKA_VERIFY_RECOVER, CKA_VERIFY_RECOVER) -> Equal
    | (CKA_DERIVE, CKA_DERIVE) -> Equal
    | (CKA_START_DATE, CKA_START_DATE) -> Equal
    | (CKA_END_DATE, CKA_END_DATE) -> Equal
    | (CKA_MODULUS, CKA_MODULUS) -> Equal
    | (CKA_MODULUS_BITS, CKA_MODULUS_BITS) -> Equal
    | (CKA_PUBLIC_EXPONENT, CKA_PUBLIC_EXPONENT) -> Equal
    | (CKA_PRIVATE_EXPONENT, CKA_PRIVATE_EXPONENT) -> Equal
    | (CKA_PRIME_1, CKA_PRIME_1) -> Equal
    | (CKA_PRIME_2, CKA_PRIME_2) -> Equal
    | (CKA_EXPONENT_1, CKA_EXPONENT_1) -> Equal
    | (CKA_EXPONENT_2, CKA_EXPONENT_2) -> Equal
    | (CKA_COEFFICIENT, CKA_COEFFICIENT) -> Equal
    | (CKA_PRIME, CKA_PRIME) -> Equal
    | (CKA_SUBPRIME, CKA_SUBPRIME) -> Equal
    | (CKA_BASE, CKA_BASE) -> Equal
    | (CKA_PRIME_BITS, CKA_PRIME_BITS) -> Equal
    | (CKA_SUBPRIME_BITS, CKA_SUBPRIME_BITS) -> Equal
    | (CKA_VALUE_LEN, CKA_VALUE_LEN) -> Equal
    | (CKA_EXTRACTABLE, CKA_EXTRACTABLE) -> Equal
    | (CKA_LOCAL, CKA_LOCAL) -> Equal
    | (CKA_NEVER_EXTRACTABLE, CKA_NEVER_EXTRACTABLE) -> Equal
    | (CKA_ALWAYS_SENSITIVE, CKA_ALWAYS_SENSITIVE) -> Equal
    | (CKA_KEY_GEN_MECHANISM, CKA_KEY_GEN_MECHANISM) -> Equal
    | (CKA_MODIFIABLE, CKA_MODIFIABLE) -> Equal
    | (CKA_EC_PARAMS, CKA_EC_PARAMS) -> Equal
    | (CKA_EC_POINT, CKA_EC_POINT) -> Equal
    | (CKA_ALWAYS_AUTHENTICATE, CKA_ALWAYS_AUTHENTICATE) -> Equal
    | (CKA_WRAP_WITH_TRUSTED, CKA_WRAP_WITH_TRUSTED) -> Equal
    | (CKA_WRAP_TEMPLATE, CKA_WRAP_TEMPLATE) -> Equal
    | (CKA_UNWRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE) -> Equal
    | (CKA_ALLOWED_MECHANISMS, CKA_ALLOWED_MECHANISMS) -> Equal
    | (CKA_CS_UNKNOWN ul1, CKA_CS_UNKNOWN ul2) ->
      let cmp = Unsigned.ULong.compare ul1 ul2 in
      if cmp = 0 then
        Equal
      else
        Not_equal cmp
    | (CKA_CLASS, _) -> assert false
    | (CKA_TOKEN, _) -> assert false
    | (CKA_PRIVATE, _) -> assert false
    | (CKA_LABEL, _) -> assert false
    | (CKA_VALUE, _) -> assert false
    | (CKA_TRUSTED, _) -> assert false
    | (CKA_CHECK_VALUE, _) -> assert false
    | (CKA_KEY_TYPE, _) -> assert false
    | (CKA_SUBJECT, _) -> assert false
    | (CKA_ID, _) -> assert false
    | (CKA_SENSITIVE, _) -> assert false
    | (CKA_ENCRYPT, _) -> assert false
    | (CKA_DECRYPT, _) -> assert false
    | (CKA_WRAP, _) -> assert false
    | (CKA_UNWRAP, _) -> assert false
    | (CKA_SIGN, _) -> assert false
    | (CKA_SIGN_RECOVER, _) -> assert false
    | (CKA_VERIFY, _) -> assert false
    | (CKA_VERIFY_RECOVER, _) -> assert false
    | (CKA_DERIVE, _) -> assert false
    | (CKA_START_DATE, _) -> assert false
    | (CKA_END_DATE, _) -> assert false
    | (CKA_MODULUS, _) -> assert false
    | (CKA_MODULUS_BITS, _) -> assert false
    | (CKA_PUBLIC_EXPONENT, _) -> assert false
    | (CKA_PRIVATE_EXPONENT, _) -> assert false
    | (CKA_PRIME_1, _) -> assert false
    | (CKA_PRIME_2, _) -> assert false
    | (CKA_EXPONENT_1, _) -> assert false
    | (CKA_EXPONENT_2, _) -> assert false
    | (CKA_COEFFICIENT, _) -> assert false
    | (CKA_PRIME, _) -> assert false
    | (CKA_SUBPRIME, _) -> assert false
    | (CKA_BASE, _) -> assert false
    | (CKA_PRIME_BITS, _) -> assert false
    | (CKA_SUBPRIME_BITS, _) -> assert false
    | (CKA_VALUE_LEN, _) -> assert false
    | (CKA_EXTRACTABLE, _) -> assert false
    | (CKA_LOCAL, _) -> assert false
    | (CKA_NEVER_EXTRACTABLE, _) -> assert false
    | (CKA_ALWAYS_SENSITIVE, _) -> assert false
    | (CKA_KEY_GEN_MECHANISM, _) -> assert false
    | (CKA_MODIFIABLE, _) -> assert false
    | (CKA_EC_PARAMS, _) -> assert false
    | (CKA_EC_POINT, _) -> assert false
    | (CKA_ALWAYS_AUTHENTICATE, _) -> assert false
    | (CKA_WRAP_WITH_TRUSTED, _) -> assert false
    | (CKA_WRAP_TEMPLATE, _) -> assert false
    | (CKA_UNWRAP_TEMPLATE, _) -> assert false
    | (CKA_ALLOWED_MECHANISMS, _) -> assert false
    | (CKA_CS_UNKNOWN _, _) -> assert false

let compare_pack (Pack a) (Pack b) = compare a b

let equal a b = compare a b = 0

let equal_pack a b = compare_pack a b = 0

let show_pack (Pack attribute) = to_string attribute

let pp_pack fmt pack = Format.pp_print_string fmt (show_pack pack)

let to_json attribute =
  try `String (to_string attribute) with
  | Invalid_argument _ -> `Null

let pack_to_json (Pack attribute) = to_json attribute

let pack_to_yojson = pack_to_json

let pack_of_yojson =
  P11_helpers.of_json_string ~typename:"attribute type" of_string

let elements =
  [ Pack CKA_CLASS
  ; Pack CKA_TOKEN
  ; Pack CKA_PRIVATE
  ; Pack CKA_LABEL
  ; Pack CKA_VALUE
  ; Pack CKA_TRUSTED
  ; Pack CKA_KEY_TYPE
  ; Pack CKA_SUBJECT
  ; Pack CKA_ID
  ; Pack CKA_SENSITIVE
  ; Pack CKA_ENCRYPT
  ; Pack CKA_DECRYPT
  ; Pack CKA_WRAP
  ; Pack CKA_UNWRAP
  ; Pack CKA_SIGN
  ; Pack CKA_SIGN_RECOVER
  ; Pack CKA_VERIFY
  ; Pack CKA_VERIFY_RECOVER
  ; Pack CKA_DERIVE
  ; Pack CKA_MODULUS
  ; Pack CKA_MODULUS_BITS
  ; Pack CKA_PUBLIC_EXPONENT
  ; Pack CKA_PRIVATE_EXPONENT
  ; Pack CKA_PRIME_1
  ; Pack CKA_PRIME_2
  ; Pack CKA_EXPONENT_1
  ; Pack CKA_EXPONENT_2
  ; Pack CKA_COEFFICIENT
  ; Pack CKA_PRIME
  ; Pack CKA_SUBPRIME
  ; Pack CKA_BASE
  ; Pack CKA_PRIME_BITS
  ; Pack CKA_SUBPRIME_BITS
  ; Pack CKA_VALUE_LEN
  ; Pack CKA_EXTRACTABLE
  ; Pack CKA_LOCAL
  ; Pack CKA_NEVER_EXTRACTABLE
  ; Pack CKA_ALWAYS_SENSITIVE
  ; Pack CKA_KEY_GEN_MECHANISM
  ; Pack CKA_MODIFIABLE
  ; Pack CKA_EC_PARAMS
  ; Pack CKA_EC_POINT
  ; Pack CKA_ALWAYS_AUTHENTICATE
  ; Pack CKA_WRAP_WITH_TRUSTED ]

let known_attribute_types = List.map (fun (Pack c) -> to_string c) elements
